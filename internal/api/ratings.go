package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/google/uuid"
)

// handleHTTPError processes common HTTP error status codes and returns appropriate errors.
// It consumes the response body and returns an error for non-success status codes.
func handleHTTPError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		var e apigen.Error
		_ = decodeJSON(resp.Body, &e)
		return fmt.Errorf("%w: %s", ErrUnauthorized, e.Message)
	case http.StatusNotFound:
		var e apigen.Error
		_ = decodeJSON(resp.Body, &e)
		return fmt.Errorf("%w: %s", ErrNotFound, e.Message)
	case http.StatusTooManyRequests:
		var e apigen.Error
		_ = decodeJSON(resp.Body, &e)
		retryAfter := 0
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if v, err := strconv.Atoi(ra); err == nil {
				retryAfter = v
			}
		}
		return RateLimitedError{RetryAfterSeconds: retryAfter, Remote: e}
	case http.StatusBadRequest:
		var e apigen.Error
		_ = decodeJSON(resp.Body, &e)
		return fmt.Errorf("%w: %s", ErrValidation, e.Message)
	default:
		var e apigen.Error
		_ = decodeJSON(resp.Body, &e)
		return RemoteError{StatusCode: resp.StatusCode, Remote: e}
	}
}

// GetRating dispatches rating retrieval based on the target type.
func (c *Client) GetRating(ctx context.Context, target RatingTarget) (RatingResult, error) { //nolint:ireturn
	switch t := target.(type) {
	case PURLTarget: // GET /ratings/purl/{purl}.
		parts := strings.Split(t.PURL, "/")
		for i, p := range parts {
			parts[i] = url.PathEscape(p)
		}
		escaped := strings.Join(parts, "/")
		return c.getRatingByPath(ctx, "/ratings/purl/"+escaped)
	case RepoTarget: // GET /ratings/repo/{org}/{repo}.
		endpointPath := "/ratings/repo/" + url.PathEscape(t.Org) + "/" + url.PathEscape(t.Repo)
		return c.getRatingByPath(ctx, endpointPath)
	case OCITarget: // GET /ratings/oci/{ref}.
		endpointPath := "/ratings/oci/" + url.PathEscape(t.Ref)
		return c.getRatingByPath(ctx, endpointPath)
	case URLTarget: // GET /ratings/url/{url}.
		endpointPath := "/ratings/url/" + url.PathEscape(t.URL)
		return c.getRatingByPath(ctx, endpointPath)
	default:
		return RatingResult{}, fmt.Errorf("unsupported rating target")
	}
}

// getRatingByPath performs a GET request to a ratings endpoint that may return 200 or 202.
func (c *Client) getRatingByPath(ctx context.Context, path string) (RatingResult, error) {
	var res RatingResult
	full := c.buildURL(path, url.Values{})
	req, err := c.newRequest(ctx, http.MethodGet, full, nil)
	if err != nil {
		return res, err
	}

	// Make a single request and handle both 200 and 202 responses
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// 200: Rating is available immediately
		var ratingResp apigen.RatingResponse
		if err := decodeJSON(resp.Body, &ratingResp); err != nil {
			return res, err
		}
		if len(ratingResp.Ratings) > 0 {
			first := ratingResp.Ratings[0]
			res.Rating = &first
		}
		return res, nil

	case http.StatusAccepted:
		// 202: Scan in progress
		var scanInProgress apigen.ScanInProgress
		if err := decodeJSON(resp.Body, &scanInProgress); err != nil {
			return res, err
		}
		res.InProgress = &scanInProgress
		return res, nil

	default:
		// Handle all error cases with the helper function
		return res, handleHTTPError(resp)
	}
}

// SubmitBatchRatings implements POST /ratings/batch.
// Per spec: 200 => BatchRatingResponse (links), 202 => ScanStatus.
// It performs a single POST and returns either the immediate response or an accepted ScanStatus.
func (c *Client) SubmitBatchRatings(ctx context.Context, reqBody apigen.BatchRatingRequest) (apigen.BatchRatingResponse, *apigen.ScanStatus, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(reqBody); err != nil {
		return apigen.BatchRatingResponse{}, nil, err
	}
	full := c.buildURL("/ratings/batch", url.Values{})
	req, err := c.newRequest(ctx, http.MethodPost, full, buf)
	if err != nil {
		return apigen.BatchRatingResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Make a single request and handle both 200 and 202 responses
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return apigen.BatchRatingResponse{}, nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// 200: Ratings are available immediately
		var batchResp apigen.BatchRatingResponse
		if err := decodeJSON(resp.Body, &batchResp); err != nil {
			return apigen.BatchRatingResponse{}, nil, err
		}
		return batchResp, nil, nil

	case http.StatusAccepted:
		// 202: Scan started, return scan status for polling
		var scanStatus apigen.ScanStatus
		if err := decodeJSON(resp.Body, &scanStatus); err != nil {
			return apigen.BatchRatingResponse{}, nil, err
		}
		return apigen.BatchRatingResponse{}, &scanStatus, nil

	default:
		// Handle all error cases with the helper function
		err := handleHTTPError(resp)
		return apigen.BatchRatingResponse{}, nil, err
	}
}

// GetScanStatus implements GET /scan-status/{scanId}.
func (c *Client) GetScanStatus(ctx context.Context, scanID uuid.UUID) (apigen.ScanStatus, error) {
	full := c.buildURL("/scan-status/"+url.PathEscape(scanID.String()), url.Values{})
	req, err := c.newRequest(ctx, http.MethodGet, full, nil)
	if err != nil {
		return apigen.ScanStatus{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return apigen.ScanStatus{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var scanStatus apigen.ScanStatus
		if err := decodeJSON(resp.Body, &scanStatus); err != nil {
			return apigen.ScanStatus{}, err
		}
		return scanStatus, nil
	}

	return apigen.ScanStatus{}, handleHTTPError(resp)
}

// WaitForScanCompletion polls a scan until completion and returns ratings for all completed targets.
// The ref must be either a scan ID or a relative path "/scan-status/{id}".
func (c *Client) WaitForScanCompletion(ctx context.Context, ref string, pollEvery time.Duration) ([]apigen.SecurityRating, error) {
	scanUUID, err := parseScanUUID(ref)
	if err != nil {
		return nil, err
	}

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		st, err := c.GetScanStatus(ctx, scanUUID)
		if err != nil {
			if d, ok := shouldWaitBeforeRetry(err); ok {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(d):
					continue
				}
			}
			return nil, err
		}

		if done, failErr := evaluateScanStatus(st); failErr != nil {
			return nil, failErr
		} else if done {
			return c.fetchAllCompletedRatings(ctx, st)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// shouldWaitBeforeRetry inspects an error and returns a backoff duration when rate limited.
func shouldWaitBeforeRetry(err error) (time.Duration, bool) {
	var rl RateLimitedError
	if errors.As(err, &rl) && rl.RetryAfterSeconds > 0 {
		return time.Duration(rl.RetryAfterSeconds) * time.Second, true
	}
	return 0, false
}

// evaluateScanStatus determines whether a scan is done or has failed; other states keep polling.
func evaluateScanStatus(st apigen.ScanStatus) (bool, error) {
	switch st.Status {
	case apigen.ScanStatusStatusCompleted:
		return true, nil
	case apigen.ScanStatusStatusFailed:
		if st.ErrorMessage != nil {
			return false, fmt.Errorf("scan failed: %s", *st.ErrorMessage)
		}
		return false, fmt.Errorf("scan failed")
	case apigen.ScanStatusStatusCanceled:
		return false, fmt.Errorf("scan canceled")
	case apigen.ScanStatusStatusQueued, apigen.ScanStatusStatusRunning, apigen.ScanStatusStatusPartial:
		return false, nil
	default:
		return false, nil
	}
}

// parseScanUUID extracts a scan UUID from either a raw UUID string or a
// relative path like "/scan-status/{id}", returning a uuid.UUID.
func parseScanUUID(ref string) (uuid.UUID, error) {
	// Handle relative path prefix.
	if after, found := strings.CutPrefix(ref, "/scan-status/"); found {
		parts := strings.Split(after, "/")
		if len(parts) > 0 && parts[0] != "" {
			ref = parts[0]
		}
	}
	u, err := uuid.Parse(ref)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid scan id: %w", err)
	}
	return u, nil
}

func (c *Client) fetchAllCompletedRatings(ctx context.Context, st apigen.ScanStatus) ([]apigen.SecurityRating, error) {
	var results []apigen.SecurityRating
	for _, t := range st.Targets {
		if t.Status == apigen.Completed && t.RatingUrl != nil && *t.RatingUrl != "" {
			r, err := c.fetchRatingRelative(ctx, *t.RatingUrl)
			if err != nil {
				return nil, err
			}
			results = append(results, r)
		}
	}
	return results, nil
}

// fetchRatingRelative treats ratingURL as a relative path under the API base and GETs a SecurityRating.
func (c *Client) fetchRatingRelative(ctx context.Context, ratingURL string) (apigen.SecurityRating, error) {
	full := c.buildURL(ratingURL, url.Values{})
	req, err := c.newRequest(ctx, http.MethodGet, full, nil)
	if err != nil {
		return apigen.SecurityRating{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return apigen.SecurityRating{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Per spec, single-rating endpoints return RatingResponse on 200.
		var ratingResp apigen.RatingResponse
		if err := decodeJSON(resp.Body, &ratingResp); err != nil {
			return apigen.SecurityRating{}, err
		}
		if len(ratingResp.Ratings) == 0 {
			return apigen.SecurityRating{}, fmt.Errorf("empty rating response")
		}
		return ratingResp.Ratings[0], nil
	}

	return apigen.SecurityRating{}, handleHTTPError(resp)
}
