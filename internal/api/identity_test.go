package api

import (
	"context"
	"testing"
)

// TestWithIdentityAndFromContext verifies storing and retrieving Identity in context.
func TestWithIdentityAndFromContext(t *testing.T) {
	t.Parallel()

	baseCtx := context.Background()

	tests := []struct {
		name      string
		identity  Identity
		expectOK  bool
		mutateCtx func(ctx context.Context) context.Context
	}{
		{
			name:     "non-anonymous with org and host",
			identity: Identity{OrgUUID: "org-123", HostUUID: "host-456", Anonymous: false},
			expectOK: true,
		},
		{
			name:     "anonymous ignores org and host",
			identity: Identity{OrgUUID: "org-ignored", HostUUID: "host-ignored", Anonymous: true},
			expectOK: true,
		},
		{
			name:     "empty identity",
			identity: Identity{},
			expectOK: true,
		},
		{
			name:     "no identity in context",
			identity: Identity{},
			expectOK: false,
			mutateCtx: func(ctx context.Context) context.Context {
				// Return original ctx without setting identity to simulate absence.
				return ctx
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := baseCtx
			if tt.mutateCtx != nil {
				ctx = tt.mutateCtx(ctx)
			} else {
				ctx = WithIdentity(ctx, tt.identity)
			}

			got, ok := IdentityFromContext(ctx)
			if ok != tt.expectOK {
				t.Fatalf("expected ok=%v, got %v", tt.expectOK, ok)
			}
			if !ok {
				return
			}

			if got != tt.identity {
				t.Fatalf("unexpected identity: got %+v, want %+v", got, tt.identity)
			}
		})
	}
}

// TestIdentityFromContextWrongType ensures safe type assertion behavior when value has wrong type.
func TestIdentityFromContextWrongType(t *testing.T) {
	t.Parallel()

	// Manually place a value under the same key with an incorrect type.
	ctx := context.WithValue(context.Background(), identityKey, "not-an-identity")

	_, ok := IdentityFromContext(ctx)
	if ok {
		t.Fatalf("expected ok=false when value has wrong type")
	}
}
