package allowlist

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/ensigniasec/run-mcp/internal/storage"
)

// Verifier handles the logic for the allowlist commands.
type Verifier struct {
	Storage *storage.Storage
}

// NewVerifier creates a new Verifier instance.
func NewVerifier(storagePath string) (*Verifier, error) {
	s, err := storage.NewStorage(storagePath)
	if err != nil {
		return nil, err
	}

	return &Verifier{Storage: s}, nil
}

// ViewAllowlist prints the current allowlist to the provided writer.
func (v *Verifier) ViewAllowlist(w io.Writer) {
	if len(v.Storage.Data.Allowlist) == 0 {
		fmt.Fprintln(w, "Allowlist is empty.")
		return
	}

	for entityType, hashes := range v.Storage.Data.Allowlist {
		fmt.Fprintf(w, "%s:\n", entityType)
		for _, hash := range hashes {
			fmt.Fprintf(w, "  - %s\n", hash)
		}
	}
}

// AddToAllowlist adds an entity to the allowlist.
func (v *Verifier) AddToAllowlist(entityType, name, hash string) error {
	logrus.Debugf("Adding to allowlist: type=%s, name=%s, hash=%s", entityType, name, hash)
	v.Storage.Data.Allowlist[entityType] = append(v.Storage.Data.Allowlist[entityType], hash)
	return v.Storage.Save()
}

// ResetAllowlist resets the allowlist.
func (v *Verifier) ResetAllowlist() error {
	logrus.Debug("Resetting allowlist")
	v.Storage.Data.Allowlist = make(map[string][]string)
	return v.Storage.Save()
}
