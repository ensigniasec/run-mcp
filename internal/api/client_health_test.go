package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
	"github.com/stretchr/testify/require"
)

func TestCheckHealth_HealthyJSON(t *testing.T) {
	var healthHits int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			healthHits++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(apigen.HealthResponse{Status: apigen.Healthy})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = "/api/v1"

	c, err := NewClient(WithBaseURL(u.String()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	status, err := c.checkHealth(ctx)
	require.NoError(t, err)
	require.Equal(t, apigen.Healthy, status)
	require.Equal(t, apigen.Healthy, c.healthStatus)
	require.Equal(t, 1, healthHits)

	// Subsequent calls should be cached (no additional hits).
	status2, err := c.checkHealth(ctx)
	require.NoError(t, err)
	require.Equal(t, apigen.Healthy, status2)
	require.Equal(t, 1, healthHits)
}

func TestCheckHealth_HealthyNoContent(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = "/api/v1"

	c, err := NewClient(WithBaseURL(u.String()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	status, err := c.checkHealth(ctx)
	require.NoError(t, err)
	require.Equal(t, apigen.Healthy, status)
	require.Equal(t, apigen.Healthy, c.healthStatus)
}

func TestCheckHealth_Unhealthy(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(apigen.Error{Error: "NOT_FOUND", Message: "missing"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = "/api/v1"

	c, err := NewClient(WithBaseURL(u.String()))
	require.ErrorIs(t, err, ErrOffline)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	status, err := c.checkHealth(ctx)
	require.Error(t, err)
	require.Equal(t, apigen.Unhealthy, status)
	require.Equal(t, apigen.Unhealthy, c.healthStatus)
}

func TestCheckHealth_SkipProbe_NoHTTPCall(t *testing.T) {
	var healthHits int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			healthHits++
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = "/api/v1"

	c, err := NewClient(WithBaseURL(u.String()), withSkipHealthProbe())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	status, err := c.checkHealth(ctx)
	require.NoError(t, err)
	require.Equal(t, apigen.Healthy, status)
	require.Equal(t, apigen.Healthy, c.healthStatus)
	require.Equal(t, 0, healthHits)
}

func TestCheckHealth_Parallel_Once(t *testing.T) {
	var healthHits int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			healthHits++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(apigen.HealthResponse{Status: apigen.Healthy})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Path = "/api/v1"

	c, err := NewClient(WithBaseURL(u.String()))
	require.NoError(t, err)

	// Fire many concurrent health checks; With sync.Once we should call server exactly once.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	const goroutines = 25
	done := make(chan struct{}, goroutines)
	for range goroutines {
		go func() {
			_, _ = c.checkHealth(ctx)
			done <- struct{}{}
		}()
	}
	for range goroutines {
		<-done
	}

	require.Equal(t, 1, healthHits)
}
