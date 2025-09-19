//nolint:testpackage // White-box tests require access to unexported identifiers in this package.
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorage_HostUUIDPersistence(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "results.json")

	s, err := NewStorage(path)
	require.NoError(t, err)

	// Initially set (generated on creation)
	require.NotEmpty(t, s.Data.HostUUID)

	// Set and save
	s.Data.HostUUID = "00000000-0000-4000-8000-000000000000"
	require.NoError(t, s.Save())

	// Read raw file to ensure field is stored
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Equal(t, "00000000-0000-4000-8000-000000000000", raw["host_uuid"])

	// Re-open and ensure persistence
	s2, err := NewStorage(path)
	require.NoError(t, err)
	require.Equal(t, "00000000-0000-4000-8000-000000000000", s2.Data.HostUUID)
}

func TestStorage_OrgUUIDPersistenceAndValidation(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "results.json")

	s, err := NewStorage(path)
	require.NoError(t, err)

	// Register a valid RFC4122 UUID and persist.
	s.Data.OrgUUID = "123e4567-e89b-12d3-a456-426614174000"
	require.NoError(t, s.Save())

	// Ensure raw file contains org_uuid
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Equal(t, "123e4567-e89b-12d3-a456-426614174000", raw["org_uuid"])

	// Reload and verify value persists.
	s2, err := NewStorage(path)
	require.NoError(t, err)
	require.Equal(t, "123e4567-e89b-12d3-a456-426614174000", s2.Data.OrgUUID)

	// Now write an invalid org uuid and ensure Load() clears it.
	s2.Data.OrgUUID = "not-a-uuid"
	require.NoError(t, s2.Save())

	s3, err := NewStorage(path)
	require.NoError(t, err)
	require.Empty(t, s3.Data.OrgUUID)
}
