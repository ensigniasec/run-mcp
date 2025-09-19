package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"strings"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	// Append api/v1 to base to simulate real base path usage.
	u.Path = "/api/v1"

	// Health probe is disabled for tests that don't expose a /health endpoint.
	c, err := NewClient(WithBaseURL(u.String()), withSkipHealthProbe())
	require.NoError(t, err)
	return c
}

func TestIdentityHeaders(t *testing.T) {
	var seenOrg, seenHost bool

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Org-Uuid") != "" {
			seenOrg = true
		}
		if r.Header.Get("X-Host-Uuid") != "" {
			seenHost = true
		}
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
			Name:           "x",
			Classification: apigen.Benign,
			LastUpdated:    now,
			Source:         apigen.Heuristic,
		}}})
	})

	c := newTestClient(t, h)

	// Default identity attaches headers.
	c.defaultIdentity = Identity{OrgUUID: "org", HostUUID: "host", Anonymous: false}
	_, err := c.GetRating(context.Background(), PURLTarget{PURL: "pkg:npm/a@1.0.0"})
	require.NoError(t, err)
	assert.True(t, seenOrg)
	assert.True(t, seenHost)

	// Context identity overrides with Anonymous=true (no headers expected).
	seenOrg, seenHost = false, false
	ctx := WithIdentity(context.Background(), Identity{Anonymous: true})
	_, err = c.GetRating(ctx, PURLTarget{PURL: "pkg:npm/a@1.0.0"})
	require.NoError(t, err)
	assert.False(t, seenOrg)
	assert.False(t, seenHost)
}

func TestGetRatingByPURL_200(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/ratings/purl/pkg:npm/a@1.0.0", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
			Name:           "a",
			Classification: apigen.Allowed,
			LastUpdated:    now,
			Source:         apigen.Heuristic,
		}}})
	})
	c := newTestClient(t, h)
	res, err := c.GetRating(context.Background(), PURLTarget{PURL: "pkg:npm/a@1.0.0"})
	require.NoError(t, err)
	require.NotNil(t, res.Rating)
	assert.Nil(t, res.InProgress)
	assert.Equal(t, "a", res.Rating.Name)
}

func TestGetRatingByPURL_202_and_Wait(t *testing.T) {
	var first = true
	scanUUID := uuid.New()
	now := time.Now().UTC()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ratings/purl/pkg:npm/a@1.0.0":
			if first {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(apigen.ScanInProgress{ScanId: scanUUID, Status: apigen.ScanInProgressStatusQueued, EstimatedCompletion: now})
			} else {
				_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{Name: "a", Classification: apigen.Allowed, LastUpdated: now, Source: apigen.Heuristic}}})
			}
		case "/api/v1/scan-status/" + scanUUID.String():
			if first {
				first = false
				_ = json.NewEncoder(w).Encode(apigen.ScanStatus{ScanId: scanUUID, Status: apigen.ScanStatusStatusRunning})
				return
			}
			_rurl := "/ratings/purl/pkg:npm/a@1.0.0"
			_ = json.NewEncoder(w).Encode(apigen.ScanStatus{
				ScanId: scanUUID, Status: apigen.ScanStatusStatusCompleted,
				Targets: []apigen.ScanTarget{{
					Identifier: apigen.TargetIdentifier{Kind: apigen.Purl, Value: "pkg:npm/a@1.0.0"},
					Name:       "a",
					Status:     apigen.Completed,
					RatingUrl:  &_rurl,
				}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "NOT_FOUND", Message: "not found"})
		}
	})

	c := newTestClient(t, h)
	res, err := c.GetRating(context.Background(), PURLTarget{PURL: "pkg:npm/a@1.0.0"})
	require.NoError(t, err)
	require.NotNil(t, res.InProgress)
	// Now wait for completion.
	ratings, err := c.WaitForScanCompletion(context.Background(), res.InProgress.ScanId.String(), 1*time.Millisecond)
	require.NoError(t, err)
	require.NotEmpty(t, ratings)
	assert.Equal(t, "a", ratings[0].Name)
}

func TestErrorMapping(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Extract the encoded URL from the last path segment and inspect its query.
		segs := strings.Split(r.URL.Path, "/")
		if len(segs) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "INTERNAL", Message: "bad path"})
			return
		}
		encoded := segs[len(segs)-1]
		decoded, _ := url.PathUnescape(encoded)
		inner, _ := url.Parse(decoded)
		kind := inner.Query().Get("kind")
		switch kind {
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "UNAUTHORIZED", Message: "auth required"})
		case "404":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "NOT_FOUND", Message: "missing"})
		case "429":
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "RATE_LIMIT", Message: "slow down"})
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "INTERNAL", Message: "boom"})
		}
	})
	c := newTestClient(t, h)

	// 401
	_, err := c.GetRating(context.Background(), URLTarget{URL: "http://example.com/x?kind=401"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))

	// 404
	_, err = c.GetRating(context.Background(), URLTarget{URL: "http://example.com/x?kind=404"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))

	// 429
	_, err = c.GetRating(context.Background(), URLTarget{URL: "http://example.com/x?kind=429"})
	var rl RateLimitedError
	require.ErrorAs(t, err, &rl)
	assert.Equal(t, 3, rl.RetryAfterSeconds)

	// 500
	_, err = c.GetRating(context.Background(), URLTarget{URL: "http://example.com/x"})
	var re RemoteError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, http.StatusInternalServerError, re.StatusCode)
}

func TestSubmitBatchRatings_200(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ratings/batch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apigen.BatchRatingResponse{Ratings: []struct {
			Identifier apigen.TargetIdentifier `json:"identifier"`
			RatingUrl  string                  `json:"rating_url"` //nolint:staticcheck
		}{{Identifier: apigen.TargetIdentifier{Kind: apigen.Purl, Value: "pkg:npm/a@1.0.0"}, RatingUrl: "/ratings/purl/pkg:npm/a@1.0.0"}}})
	})
	c := newTestClient(t, h)
	req := apigen.BatchRatingRequest{Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/a@1.0.0"}}}
	resp, accepted, err := c.SubmitBatchRatings(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, accepted)
	require.Len(t, resp.Ratings, 1)
	assert.Equal(t, "/ratings/purl/pkg:npm/a@1.0.0", resp.Ratings[0].RatingUrl)
}

func TestSubmitBatchRatings_400(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(apigen.Error{Error: "VALIDATION", Message: "invalid"})
	})
	c := newTestClient(t, h)
	_, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrValidation))
}
