package api

// Build-time variables injected via -ldflags -X.
// Defaults are for local dev and tests.
//
//nolint:gochecknoglobals // these are set at build time
var (
	BuildVersion = "dev"
	BuildCommit  = "none"
	BuildDate    = "unknown"
)
