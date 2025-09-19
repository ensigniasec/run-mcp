 ### API Client Layer (internal/api)

This package provides a thin, well-tested HTTP client for the Control Plane API described in `docs/api-spec.yaml`.

We use generated OpenAPI types from `internal/api-gen` (package `apigen`) directly for all request/response models to avoid drift and keep behavior aligned with the spec.

### Goals
- Decouple transport concerns with a focused client and small helpers.
- Stable, testable interfaces which remain compatible as the API evolves.
- Resilient HTTP behavior with timeouts and typed errors.

### Key Decisions
- Health endpoint: used internally for a one-time readiness probe, not part of the exported interface.
- Identity handling: carried via `context.Context`. Helpers: `WithIdentity(ctx, Identity)` and `IdentityFromContext(ctx)`; a default identity can be set on the client and overridden per call via context.
- Single-rating endpoints: 200 returns `apigen.RatingResponse` (we surface the first rating); 202 returns `apigen.ScanInProgress` with polling helpers.
- Batch ratings: 200 returns `apigen.BatchRatingResponse` (links); 202 returns `apigen.ScanStatus` (pending). Client returns `(BatchRatingResponse, *ScanStatus, error)` to distinguish immediate vs accepted.
- Auth: All endpoints require a specific publishable key via `Authorization: Bearer <publishable_key>`.

### Public Interfaces (internal)
```go
// Identity is attached to requests if not Anonymous.
type Identity struct {
    OrgUUID   string
    HostUUID  string
    Anonymous bool
}

// Context helpers.
func WithIdentity(parent context.Context, id Identity) context.Context
func IdentityFromContext(ctx context.Context) (Identity, bool)

// RatingsClient is the main transport interface used by the scanner.
type RatingsClient interface {
    GetRating(ctx context.Context, target RatingTarget) (RatingResult, error)
    SubmitBatchRatings(ctx context.Context, req apigen.BatchRatingRequest) (apigen.BatchRatingResponse, *apigen.ScanStatus, error)
    GetScanStatus(ctx context.Context, scanID uuid.UUID) (apigen.ScanStatus, error)

    // Optional helper: polls when a prior call returned 202.
    WaitForScanCompletion(ctx context.Context, ref string, pollEvery time.Duration) ([]apigen.SecurityRating, error)
}

// Client construction.
type ClientOption func(*Client)
func NewClient(opts ...ClientOption) (*Client, error)
```

### Types
- We use the generated types from `internal/api-gen/types.gen.go` (package `apigen`) directly: `SecurityRating`, `RatingResponse`, `BatchRatingRequest`, `BatchRatingResponse`, `ScanInProgress`, `ScanStatus`, `TargetIdentifier`, `IdentifierKind`, etc.
- Internal convenience types:
```go
// RatingResult represents either a final rating (200) or an async in-progress response (202).
type RatingResult struct {
    Rating     *apigen.SecurityRating // 200 response
    InProgress *apigen.ScanInProgress // 202 response
}

// RatingTarget captures supported targets using generated IdentifierKind.
type RatingTarget interface { kind() apigen.IdentifierKind }
```

### HTTP Behavior
- Standard `net/http` client with a sane default timeout.
- Conditional headers `X-Org-Uuid` and `X-Host-Uuid` when `Anonymous == false`.
- Limited retries for idempotent GETs on transient errors and HTTP 429/5xx, honoring `Retry-After`.
- Strict JSON decoding with clear error surfacing (`apigen.Error` mapped to typed errors).

### Endpoints Covered
- `GET /ratings/purl/{purl}` → `RatingResponse` or `ScanInProgress`.
- `GET /ratings/repo/{org}/{repo}` → `RatingResponse` or `ScanInProgress`.
- `GET /ratings/oci/{ref}` → `RatingResponse` or `ScanInProgress`.
- `GET /ratings/url/{url}` → `RatingResponse` or `ScanInProgress`.
- `POST /ratings/batch` → `BatchRatingResponse` (200) or `ScanStatus` (202).
- `GET /scan-status/{scanId}` → `ScanStatus`.
- `GET /health` is available internally for diagnostics.

### Error Handling
- Typed errors: `ErrUnauthorized`, `ErrNotFound`, `ErrValidation`, `ErrOffline`.
- Structured errors: `RateLimitedError` with `Retry-After`, and `RemoteError` with status code and optional request ID.

### Testing Strategy
- Unit tests: `httptest.Server` covering paths, headers, and all response codes.
- Contract tests: optional against an OpenAPI mock derived from `docs/api-spec.yaml`.
- Schema drift guard: `task api-spec:check`.

### Taskfile hooks
- `task test` → run standard tests.
- `task test-all` → run all tests.
- `task api-spec:gen` → regenerate types from `docs/api-spec.yaml`.
- `task api-spec:check` → verify generated types are up-to-date and committed.
