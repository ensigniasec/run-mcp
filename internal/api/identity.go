package api

import "context"

// Identity carries optional request identity.
// When Anonymous is true, OrgUUID and HostUUID are ignored.
type Identity struct {
	OrgUUID   string
	HostUUID  string
	Anonymous bool
}

type identityKeyType struct{}

//nolint:gochecknoglobals // this is zero-size sentinel type.
var identityKey = identityKeyType{}

// WithIdentity returns a new context with the provided identity.
func WithIdentity(parent context.Context, id Identity) context.Context {
	return context.WithValue(parent, identityKey, id)
}

// IdentityFromContext extracts an Identity from context if present.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	v := ctx.Value(identityKey)
	if v == nil {
		return Identity{}, false
	}
	id, ok := v.(Identity)
	return id, ok
}
