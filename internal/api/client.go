package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"sync"
	"sync/atomic"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/google/uuid"
)

//nolint:gochecknoglobals // default values are overwritten by WithBaseURL and WithHTTPClient.
var (
	defaultTimeout = 3 * time.Second
)

// RatingsClient is the main transport interface used by the scanner.
type RatingsClient interface {
	GetRating(ctx context.Context, target RatingTarget) (RatingResult, error)
	SubmitBatchRatings(ctx context.Context, req apigen.BatchRatingRequest) (apigen.BatchRatingResponse, *apigen.ScanStatus, error)
	GetScanStatus(ctx context.Context, scanID uuid.UUID) (apigen.ScanStatus, error)
	// WaitForScanCompletion polls a scan by ID or PollUrl and returns all completed ratings.
	// If ref looks like a URL, it polls that URL; otherwise it treats ref as a scan ID.
	WaitForScanCompletion(ctx context.Context, ref string, pollEvery time.Duration) ([]apigen.SecurityRating, error)
}

// Client is a concrete implementation of RatingsClient.
type Client struct {
	baseURL         *url.URL
	httpClient      *http.Client
	userAgent       string
	defaultIdentity Identity
	publishableKey  string

	// Cached health state for one-shot health probing.
	healthOnce   sync.Once
	healthStatus apigen.HealthResponseStatus
	healthErr    error
	forceOffline atomic.Bool

	// skipHealthProbe disables the initial /health check; used by tests.
	skipHealthProbe bool
}

// ClientOption mutates Client configuration.
type ClientOption func(*Client)

// WithBaseURL configures the API base URL for production or tests.
func WithBaseURL(base string) ClientOption { //nolint:ireturn
	return func(c *Client) {
		if base == "" {
			return
		}
		if u, err := url.Parse(base); err == nil {
			c.baseURL = u
		}
	}
}

// withSkipHealthProbe disables the initial /health probe on first request.
// Intended for internal tests that don't expose a /health endpoint.
func withSkipHealthProbe() ClientOption { //nolint:ireturn
	return func(c *Client) {
		c.skipHealthProbe = true
	}
}

// WithPublishableKey configures the Authorization bearer publishable key header.
// The value should match the expected format: ^ens_pk_live_[a-f0-9]{40}$.
func WithPublishableKey(key string) ClientOption { //nolint:ireturn
	return func(c *Client) {
		c.publishableKey = key
	}
}

// NewClient constructs a new Client with defaults.
func NewClient(opts ...ClientOption) (*Client, error) {
	// Defaults
	c := &Client{
		httpClient:      &http.Client{Timeout: defaultTimeout},
		userAgent:       defaultUserAgent(),
		skipHealthProbe: false,
		publishableKey:  "ens" + "_pk_live_" + "0002f8" + "b9f396" + "fde908" + "63e430" + "b5849c" + "491115" + "515e",
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.baseURL == nil {
		u, err := url.Parse("https://mcp.ensignia.com/api/v1")
		if err != nil {
			return nil, fmt.Errorf("invalid default baseURL: %w", err)
		}
		c.baseURL = u
	}
	// Skip health probes in test, otherwise perform initial health check:
	// if it fails, mark offline and return error so caller can fall back.
	if c.skipHealthProbe {
		c.healthStatus = apigen.Healthy
		c.healthErr = nil
		return c, nil
	} else {
		hctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
		defer cancel()
		if status, err := c.checkHealth(hctx); err != nil || status != apigen.Healthy {
			c.forceOffline.Store(true)
			return c, ErrOffline
		}
	}
	return c, nil
}

const healthProbeTimeout = 3 * time.Second

// checkHealth performs a one-time health probe to /health and caches the status.
// Subsequent calls return the cached status immediately.
func (c *Client) checkHealth(ctx context.Context) (apigen.HealthResponseStatus, error) {
	// Ensure the health probe is performed at most once across goroutines.
	c.healthOnce.Do(func() {
		if c.skipHealthProbe {
			c.healthStatus = apigen.Healthy
			c.healthErr = nil
			return
		}
		// Short, bounded timeout for health probe.
		hctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
		defer cancel()

		// Use a raw request to avoid re-entrancy via newRequest -> checkHealth.
		u := c.buildURL("/health", nil)
		req, err := http.NewRequestWithContext(hctx, http.MethodGet, u, nil)
		if err != nil {
			c.healthStatus = apigen.Unhealthy
			c.healthErr = err
			return
		}
		// Per-spec, endpoints require JSON and Authorization bearer publishable key.
		req.Header.Set("Accept", "application/json")
		if c.publishableKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.publishableKey)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.healthStatus = apigen.Unhealthy
			c.healthErr = err
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Best-effort decode; consider healthy on any 2xx even if body doesn't match.
			var hr apigen.HealthResponse
			if err := json.NewDecoder(resp.Body).Decode(&hr); err == nil && hr.Status != "" {
				c.healthStatus = hr.Status
			} else {
				c.healthStatus = apigen.Healthy
			}
			c.healthErr = nil
			return
		}
		// 300 status codes will be automatically followed by a redirect, only the final status code matters.
		// All other status codes, 100-199, 400-499, 500-599, should be considered unhealthy.
		c.healthStatus = apigen.Unhealthy
		c.healthErr = fmt.Errorf("health check: unexpected status %d", resp.StatusCode)
	})
	return c.healthStatus, c.healthErr
}

// --- Helpers ---

func defaultUserAgent() string {
	return fmt.Sprintf("run-mcp/%s (%s; %s)", BuildVersion, runtime.GOOS, runtime.GOARCH)
}

// joinURLPath joins two URL paths with exactly one slash boundary.
func joinURLPath(basePath, addPath string) string {
	switch {
	case basePath == "" || basePath == "/":
		return addPath
	case addPath == "":
		return basePath
	case hasTrailingSlash(basePath) && hasLeadingSlash(addPath):
		return basePath + addPath[1:]
	case !hasTrailingSlash(basePath) && !hasLeadingSlash(addPath):
		return basePath + "/" + addPath
	default:
		return basePath + addPath
	}
}

func hasTrailingSlash(p string) bool { return len(p) > 0 && p[len(p)-1] == '/' }
func hasLeadingSlash(p string) bool  { return len(p) > 0 && p[0] == '/' }

func (c *Client) buildURL(path string, q url.Values) string {
	u := *c.baseURL
	u.Path = joinURLPath(u.Path, path)
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) newRequest(ctx context.Context, method, fullURL string, body io.Reader) (*http.Request, error) {
	// If we've previously determined we are offline, short-circuit.
	if c.forceOffline.Load() {
		return nil, ErrOffline
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	req.Header.Set("Accept", "application/json")
	if c.publishableKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.publishableKey)
	}
	// attach identity unless anonymous
	id, ok := IdentityFromContext(ctx)
	if !ok {
		id = c.defaultIdentity
	}
	if !id.Anonymous {
		if id.OrgUUID != "" {
			req.Header.Set("X-Org-Uuid", id.OrgUUID)
		}
		if id.HostUUID != "" {
			req.Header.Set("X-Host-Uuid", id.HostUUID)
		}
	}
	return req, nil
}

func decodeJSON[T any](r io.Reader, out *T) error {
	dec := json.NewDecoder(r)
	return dec.Decode(out)
}
