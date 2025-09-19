package allowlist

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureBuffer returns a buffer for capturing output.
func captureBuffer() *bytes.Buffer { return &bytes.Buffer{} }

func TestNewVerifier_CreatesStorage(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "storage.json")

	v, err := NewVerifier(storagePath)
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.NotEmpty(t, v.Storage.Data.HostUUID)

	// Storage file should be created on first Save.
	require.NoError(t, v.Storage.Save())
	if _, err := os.Stat(storagePath); err != nil {
		t.Fatalf("expected storage file to exist: %v", err)
	}
}

func TestViewAllowlist_Empty(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "storage.json")

	v, err := NewVerifier(storagePath)
	require.NoError(t, err)

	buf := captureBuffer()
	v.ViewAllowlist(buf)
	out := buf.String()

	assert.Contains(t, out, "Allowlist is empty.")
}

func TestAddToAllowlist_Persists(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "storage.json")

	v, err := NewVerifier(storagePath)
	require.NoError(t, err)

	// Add an entry and persist.
	require.NoError(t, v.AddToAllowlist("server", "filesystem", "hash123"))

	// Re-open storage via a new verifier to ensure persistence on disk.
	v2, err := NewVerifier(storagePath)
	require.NoError(t, err)
	hashes := v2.Storage.Data.Allowlist["server"]
	require.Len(t, hashes, 1)
	assert.Equal(t, "hash123", hashes[0])

	// View should print the entry.
	buf := captureBuffer()
	v2.ViewAllowlist(buf)
	out := buf.String()
	assert.Contains(t, out, "server:")
	assert.Contains(t, out, "hash123")
}

func TestResetAllowlist_ClearsEntries(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "storage.json")

	v, err := NewVerifier(storagePath)
	require.NoError(t, err)

	// Seed with two entries under the same type to ensure full reset.
	require.NoError(t, v.AddToAllowlist("server", "filesystem", "hash123"))
	require.NoError(t, v.AddToAllowlist("server", "git", "hash456"))

	// Reset and verify persistence.
	require.NoError(t, v.ResetAllowlist())

	v2, err := NewVerifier(storagePath)
	require.NoError(t, err)
	assert.Equal(t, 0, len(v2.Storage.Data.Allowlist))

	buf := captureBuffer()
	v2.ViewAllowlist(buf)
	out := buf.String()
	assert.Contains(t, out, "Allowlist is empty.")
}
