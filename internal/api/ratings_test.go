package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRating_Repo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		org      string
		repo     string
		expected string
	}{
		{
			name:     "simple",
			org:      "ensignia",
			repo:     "run-mcp",
			expected: "/api/v1/ratings/repo/ensignia/run-mcp",
		},
		{
			name:     "needs-escaping",
			org:      "acme/co",
			repo:     "repo#name",
			expected: "/api/v1/ratings/repo/acme%2Fco/repo%23name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.expected, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				now := time.Now().UTC()
				_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
					Name:           "repo",
					Classification: apigen.Allowed,
					LastUpdated:    now,
					Source:         apigen.Heuristic,
				}}})
			})
			c := newTestClient(t, h)
			res, err := c.GetRating(context.Background(), RepoTarget{Org: tt.org, Repo: tt.repo})
			require.NoError(t, err)
			require.NotNil(t, res.Rating)
			assert.Nil(t, res.InProgress)
		})
	}
}

func TestGetRating_OCI(t *testing.T) {
	t.Parallel()

	ref := "ghcr.io/acme/image:1.2.3@sha256:abcdef"
	expected := "/api/v1/ratings/oci/" + url.PathEscape(ref)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expected, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
			Name:           "oci",
			Classification: apigen.Allowed,
			LastUpdated:    now,
			Source:         apigen.Heuristic,
		}}})
	})

	c := newTestClient(t, h)
	res, err := c.GetRating(context.Background(), OCITarget{Ref: ref})
	require.NoError(t, err)
	require.NotNil(t, res.Rating)
}

func TestGetRating_URL(t *testing.T) {
	t.Parallel()

	raw := "https://example.com/a path?q=1&x=y"
	expected := "/api/v1/ratings/url/" + url.PathEscape(raw)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expected, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
			Name:           "url",
			Classification: apigen.Allowed,
			LastUpdated:    now,
			Source:         apigen.Heuristic,
		}}})
	})

	c := newTestClient(t, h)
	res, err := c.GetRating(context.Background(), URLTarget{URL: raw})
	require.NoError(t, err)
	require.NotNil(t, res.Rating)
}

func TestGetRating_PURL(t *testing.T) {
	t.Parallel()

	// The purl contains a slash as part of the scope, which must be preserved as a path separator
	// while escaping the segment value ("@scope" -> "%40scope").
	purl := "pkg:npm/@scope/a@1.0.0"
	expected := "/api/v1/ratings/purl/pkg:npm/@scope/a@1.0.0"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expected, r.URL.Path)
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
	res, err := c.GetRating(context.Background(), PURLTarget{PURL: purl})
	require.NoError(t, err)
	require.NotNil(t, res.Rating)
}

func TestSubmitBatchRatings_202_Accepted(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ratings/batch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(apigen.ScanStatus{Status: apigen.ScanStatusStatusQueued})
	})
	c := newTestClient(t, h)
	_, accepted, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{})
	require.NoError(t, err)
	require.NotNil(t, accepted)
}

func TestSubmitBatchRatings_401_Unauthorized(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(apigen.Error{Error: "UNAUTHORIZED", Message: "invalid auth token"})
	})
	c := newTestClient(t, h)
	_, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))
	assert.Contains(t, err.Error(), "invalid auth token")
}

func TestSubmitBatchRatings_429_RateLimited(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(apigen.Error{Error: "RATE_LIMIT", Message: "too many requests"})
	})
	c := newTestClient(t, h)
	_, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.Error(t, err)
	var rl RateLimitedError
	require.ErrorAs(t, err, &rl)
	assert.Equal(t, 30, rl.RetryAfterSeconds)
}

func TestSubmitBatchRatings_415_UnsupportedMediaType(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate the exact scenario that was causing 415 errors
		if r.Header.Get("Content-Type") != "application/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "UNSUPPORTED_MEDIA_TYPE", Message: "Content-Type must be application/json"})
			return
		}
		// If Content-Type is correct, return a successful response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apigen.BatchRatingResponse{Ratings: []struct {
			Identifier apigen.TargetIdentifier `json:"identifier"`
			RatingUrl  string                  `json:"rating_url"` //nolint:staticcheck
		}{{Identifier: apigen.TargetIdentifier{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}, RatingUrl: "/ratings/purl/pkg%3Anpm%2Ftest%401.0.0"}}})
	})
	c := newTestClient(t, h)
	resp, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	// This should NOT error because our implementation correctly sets Content-Type
	require.NoError(t, err)
	require.Len(t, resp.Ratings, 1)
}

func TestSubmitBatchRatings_503_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(apigen.Error{Error: "SERVICE_UNAVAILABLE", Message: "backend temporarily unavailable"})
	})
	c := newTestClient(t, h)
	_, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.Error(t, err)
	var re RemoteError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, http.StatusServiceUnavailable, re.StatusCode)
}

func TestSubmitBatchRatings_MaxBatchSize(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apigen.BatchRatingRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, 50, len(req.Identifiers), "API spec allows max 50 items")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(apigen.ScanStatus{Status: apigen.ScanStatusStatusQueued})
	})
	c := newTestClient(t, h)

	// Create batch request with 50 identifiers (max allowed)
	identifiers := make([]apigen.TargetIdentifier, 50)
	for i := range 50 {
		identifiers[i] = apigen.TargetIdentifier{
			Kind:  apigen.Purl,
			Value: fmt.Sprintf("pkg:npm/test-%d@1.0.0", i),
		}
	}

	_, accepted, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: identifiers,
	})
	require.NoError(t, err)
	require.NotNil(t, accepted)
}

func TestSubmitBatchRatings_MixedIdentifierTypes(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apigen.BatchRatingRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		// Verify we received mixed types
		assert.Len(t, req.Identifiers, 4)
		kinds := make(map[apigen.IdentifierKind]bool)
		for _, id := range req.Identifiers {
			kinds[id.Kind] = true
		}
		assert.Len(t, kinds, 4, "should have 4 different identifier types")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apigen.BatchRatingResponse{
			Ratings: []struct {
				Identifier apigen.TargetIdentifier `json:"identifier"`
				RatingUrl  string                  `json:"rating_url"` //nolint:staticcheck
			}{
				{Identifier: req.Identifiers[0], RatingUrl: "/ratings/purl/pkg%3Anpm%2Ftest%401.0.0"},
				{Identifier: req.Identifiers[1], RatingUrl: "/ratings/repo/example/repo"},
				{Identifier: req.Identifiers[2], RatingUrl: "/ratings/oci/registry.example.com%2Fimage%3Alatest"},
				{Identifier: req.Identifiers[3], RatingUrl: "/ratings/url/https%3A%2F%2Fexample.com"},
			},
		})
	})
	c := newTestClient(t, h)

	resp, accepted, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{
			{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"},
			{Kind: apigen.Repo, Value: "example/repo"},
			{Kind: apigen.Oci, Value: "registry.example.com/image:latest"},
			{Kind: apigen.Url, Value: "https://example.com"},
		},
	})
	require.NoError(t, err)
	require.Nil(t, accepted)
	require.Len(t, resp.Ratings, 4)
}

func TestSubmitBatchRatings_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called due to cancelled context")
	})
	c := newTestClient(t, h)

	_, _, err := c.SubmitBatchRatings(ctx, apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestSubmitBatchRatings_MalformedJSONResponse(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write malformed JSON
		_, _ = w.Write([]byte(`{"ratings": [invalid json}`))
	})
	c := newTestClient(t, h)

	_, _, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid character")
}

func TestSubmitBatchRatings_EmptyResponse(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apigen.BatchRatingResponse{Ratings: []struct {
			Identifier apigen.TargetIdentifier `json:"identifier"`
			RatingUrl  string                  `json:"rating_url"` //nolint:staticcheck
		}{}})
	})
	c := newTestClient(t, h)

	resp, accepted, err := c.SubmitBatchRatings(context.Background(), apigen.BatchRatingRequest{
		Identifiers: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/test@1.0.0"}},
	})
	require.NoError(t, err)
	require.Nil(t, accepted)
	assert.Empty(t, resp.Ratings)
}

func TestShouldWaitBeforeRetry(t *testing.T) {
	t.Parallel()

	d, ok := shouldWaitBeforeRetry(RateLimitedError{RetryAfterSeconds: 5})
	assert.True(t, ok)
	assert.Equal(t, 5*time.Second, d)

	d, ok = shouldWaitBeforeRetry(RemoteError{StatusCode: 500})
	assert.False(t, ok)
	assert.Equal(t, time.Duration(0), d)
}

func TestEvaluateScanStatus(t *testing.T) {
	t.Parallel()

	// Completed.
	done, err := evaluateScanStatus(apigen.ScanStatus{Status: apigen.ScanStatusStatusCompleted})
	assert.NoError(t, err)
	assert.True(t, done)

	// Failed with message.
	msg := "boom"
	done, err = evaluateScanStatus(apigen.ScanStatus{Status: apigen.ScanStatusStatusFailed, ErrorMessage: &msg})
	assert.Error(t, err)
	assert.False(t, done)
	assert.Contains(t, err.Error(), msg)

	// Failed without message.
	done, err = evaluateScanStatus(apigen.ScanStatus{Status: apigen.ScanStatusStatusFailed})
	assert.Error(t, err)
	assert.False(t, done)
	assert.EqualError(t, err, "scan failed")

	// Canceled.
	done, err = evaluateScanStatus(apigen.ScanStatus{Status: apigen.ScanStatusStatusCanceled})
	assert.Error(t, err)
	assert.False(t, done)

	// Queued/Running/Partial.
	for _, s := range []apigen.ScanStatusStatus{apigen.ScanStatusStatusQueued, apigen.ScanStatusStatusRunning, apigen.ScanStatusStatusPartial} {
		done, err = evaluateScanStatus(apigen.ScanStatus{Status: s})
		assert.NoError(t, err)
		assert.False(t, done)
	}
}

func TestParseScanUUID(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	// Raw.
	got, err := parseScanUUID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, got)

	// Relative.
	got, err = parseScanUUID("/scan-status/" + id.String())
	require.NoError(t, err)
	assert.Equal(t, id, got)

	// Invalid.
	_, err = parseScanUUID("not-a-uuid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scan id")
}

func TestFetchRatingRelative_Empty(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ratings/purl/pkg:npm/a@1.0.0" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{}})
	})
	c := newTestClient(t, h)
	_, err := c.fetchRatingRelative(context.Background(), "/ratings/purl/pkg:npm/a@1.0.0")
	require.Error(t, err)
	assert.EqualError(t, err, "empty rating response")
}

func TestFetchAllCompletedRatings(t *testing.T) {
	t.Parallel()

	ratingURL := "/ratings/url/" + url.PathEscape("https://example.com/foo")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1"+ratingURL {
			w.Header().Set("Content-Type", "application/json")
			now := time.Now().UTC()
			_ = json.NewEncoder(w).Encode(apigen.RatingResponse{Ratings: []apigen.SecurityRating{{
				Name:           "x",
				Classification: apigen.Benign,
				LastUpdated:    now,
				Source:         apigen.Heuristic,
			}}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	c := newTestClient(t, h)

	// Build a ScanStatus with a completed target with rating URL, and others that should be ignored.
	st := apigen.ScanStatus{Targets: []apigen.ScanTarget{
		{Status: apigen.Completed, RatingUrl: &ratingURL},
		{Status: apigen.Running},   // ignored
		{Status: apigen.Completed}, // missing url, ignored
	}}

	ratings, err := c.fetchAllCompletedRatings(context.Background(), st)
	require.NoError(t, err)
	require.Len(t, ratings, 1)
	assert.Equal(t, "x", ratings[0].Name)
}
