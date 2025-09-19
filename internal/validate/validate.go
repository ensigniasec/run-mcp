package validate

// This package adds struct and field validation as a thin wrapper around the go-playground/validator package.
//
// e.g. internal/storage/storage.go
//   type Data struct {
// 		 ...
//       HostUUID	string	`json:"host_uuid,omitempty" validate:"omitempty,uuid4"`
//       OrgUUID    string	`json:"org_uuid,omitempty" validate:"omitempty,uuid_rfc4122"`
//   }
//
// This allows for consistent validation of uuid4 and uuid_rfc4122 tags.

import (
	"sync"

	"github.com/go-playground/validator/v10"
)

// validatorInstance is a shared validator for the application.
// It is initialized once and reused to avoid repeated allocations.
//
//nolint:gochecknoglobals // Shared validator singleton.
var (
	validatorOnce sync.Once
	validatorInst *validator.Validate
)

// get returns a process-wide singleton of the validator.
func get() *validator.Validate {
	validatorOnce.Do(func() {
		validatorInst = validator.New(validator.WithRequiredStructEnabled())
		// Built-in tags include: uuid4, uuid_rfc4122, cve, etc.
		// We can register custom tags here in the future if needed.
	})
	return validatorInst
}

// Struct validates a struct using the shared validator instance.
func Struct(v any) error {
	return get().Struct(v)
}

// Var validates a single variable against the provided tag constraints.
func Var(field any, tag string) error {
	return get().Var(field, tag)
}
