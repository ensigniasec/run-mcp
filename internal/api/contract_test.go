package api

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

//nolint:gochecknoglobals // test flag for toggling mock contract tests
var mocks = flag.Bool("mocks", false, "only perform local tests (skip network/mock tests)")

// TestContract_WithOpenAPIMock exercises the client against a running muonsoft/openapi-mock
// server using the repo endpoint. Skips when -mocks is set or when the mock is unreachable.
func TestContract_WithOpenAPIMock(t *testing.T) {
	if !*mocks {
		t.Skip("offline mode: skipping mocks contract test")
	}

	base := os.Getenv("API_BASE_URL")
	if base == "" {
		// Default to localhost mock port used by Taskfile.
		base = "http://run-mcp-mock:3000/api/v1"
	}

	// Quick connectivity check; skip if not reachable to avoid flaky CI.
	if !reachable(base) {
		t.Skipf("mock server not reachable at %s; set API_BASE_URL or run task api:mock", base)
	}

	c, err := NewClient(WithBaseURL(base), withSkipHealthProbe())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use examples from the spec where possible.
	res, err := c.GetRating(ctx, RepoTarget{Org: "modelcontextprotocol", Repo: "servers"})
	if err != nil {
		t.Fatalf("GetRating(repo): %v", err)
	}
	if res.Rating == nil && res.InProgress == nil {
		t.Fatalf("expected either Rating or InProgress, got nil")
	}
}

func reachable(baseURL string) bool {
	// crude host:port dial with short timeout.
	cl := &http.Client{Timeout: 500 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := cl.Do(req)
	if err != nil {
		// If URL parsing fails for /health path, fallback to raw TCP dial.
		// Try to extract host:port from the base URL.
		_, err2 := net.DialTimeout("tcp", "run-mcp-mock:3000", 300*time.Millisecond)
		return err2 == nil
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}
