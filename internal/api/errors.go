package api

import (
	"errors"
	"fmt"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
)

// Sentinel and typed errors for transport-level reporting.
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrNotFound     = errors.New("not found")
	ErrValidation   = errors.New("validation error")
	ErrOffline      = errors.New("offline")
)

// RateLimitedError includes optional retry-after seconds.
type RateLimitedError struct {
	RetryAfterSeconds int
	Remote            apigen.Error
}

func (e RateLimitedError) Error() string {
	if e.RetryAfterSeconds > 0 {
		return fmt.Sprintf("rate limited, retry after %ds: %s", e.RetryAfterSeconds, e.Remote.Message)
	}
	return fmt.Sprintf("rate limited: %s", e.Remote.Message)
}

// RemoteError wraps non-specific remote errors with status code and optional request ID.
type RemoteError struct {
	StatusCode int
	Remote     apigen.Error
}

func (e RemoteError) Error() string {
	if e.Remote.RequestId != nil && *e.Remote.RequestId != "" {
		return fmt.Sprintf("remote error %d (%s): %s [request_id=%s]", e.StatusCode, e.Remote.Error, e.Remote.Message, *e.Remote.RequestId)
	}
	if e.Remote.Error != "" {
		return fmt.Sprintf("remote error %d (%s): %s", e.StatusCode, e.Remote.Error, e.Remote.Message)
	}
	return fmt.Sprintf("remote error %d", e.StatusCode)
}
