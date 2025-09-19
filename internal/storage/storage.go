package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/ensigniasec/run-mcp/internal/validate"
)

// Data represents the structure of the storage file.
type Data struct {
	ScannedEntities map[string]map[string]string `json:"scanned_entities"`
	Allowlist       map[string][]string          `json:"allowlist"`
	Denylist        map[string][]string          `json:"denylist"`
	// TODO: add denylist functionality in cli
	HostUUID string `json:"host_uuid,omitempty" validate:"omitempty,uuid_rfc4122"`
	OrgUUID  string `json:"org_uuid,omitempty" validate:"omitempty,uuid_rfc4122"`
}

// Storage handles the loading and saving of the storage file.
type Storage struct {
	Path string `validate:"required,filepath"`
	Data Data
}

// NewStorage creates a new Storage instance.
func NewStorage(path string) (*Storage, error) {
	expandedPath, err := expandTilde(path)
	if err != nil {
		return nil, err
	}

	s := &Storage{
		Path: expandedPath,
		Data: Data{
			ScannedEntities: make(
				map[string]map[string]string,
			), // TODO: consider unique identifier for each scanned entity - see: ID.md
			Allowlist: make(map[string][]string),
			Denylist:  make(map[string][]string),
			HostUUID:  "",
		},
	}

	// Attempt to read system-wide managed config for host/org UUIDs.
	if sysOrg, sysHost := readSystemManagedConfig(); sysOrg != "" || sysHost != "" {
		if sysOrg != "" {
			s.Data.OrgUUID = sysOrg
		}
		if sysHost != "" {
			s.Data.HostUUID = sysHost
		}
	}

	if err := s.Load(); err != nil {
		// If the file doesn't exist, we can ignore the error.
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	// Ensure HostUUID present: if not provided by system config and not present in storage, generate one.
	if s.Data.HostUUID == "" {
		s.Data.HostUUID = uuid.NewString()
	}

	return s, nil
}

// NewOrExistingStorage returns existing storage if the file exists, or creates a new one otherwise.
// When creating a new storage, it writes the initial structure to disk immediately.
// Additionally, this ensures a HostUUID is present; if missing, it is generated and saved.
func NewOrExistingStorage(path string) (*Storage, error) {
	expandedPath, err := expandTilde(path)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(expandedPath); err == nil {
		// Config already exists, load it.
		s, err := NewStorage(path)
		if err != nil {
			return nil, err
		}
		// Do not overwrite values; NewStorage already loaded system config if present and generated HostUUID if missing.
		return s, nil
	} else if os.IsNotExist(err) {
		// Config doesn't exist, create it.
		s, err := NewStorage(path)
		if err != nil {
			return nil, err
		}
		// Persist initial storage (results scaffold and identifiers) to disk.
		if err := s.Save(); err != nil {
			return nil, err
		}
		return s, nil
	}
	return nil, err
}

func (s *Storage) Load() error {
	logrus.Debug("Loading storage file from: ", s.Path)
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &s.Data); err != nil {
		return err
	}

	// Validate loaded data and self-heal when possible.
	if err := validate.Struct(s.Data); err != nil {
		changed := false
		// Ensure HostUUID is a valid v4.
		if s.Data.HostUUID == "" || validate.Var(s.Data.HostUUID, "uuid4") != nil {
			s.Data.HostUUID = uuid.NewString()
			changed = true
		}
		// If OrgUUID present but invalid, clear it.
		if s.Data.OrgUUID != "" && validate.Var(s.Data.OrgUUID, "uuid_rfc4122") != nil {
			logrus.Warn("Invalid org_uuid found in storage; clearing.")
			s.Data.OrgUUID = ""
			changed = true
		}
		if changed {
			if err := s.Save(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Save writes the storage data to the file.
func (s *Storage) Save() error {
	logrus.Debug("Saving storage file to: ", s.Path)
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.Path, data, 0o600)
}

// expandTilde expands the tilde in a path to the user's home directory.
func expandTilde(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, path[1:]), nil
}

// readSystemManagedConfig reads org_uuid and host_uuid from the managed system-wide config
// at /Library/Application Support/run-mcp/config.yaml. YAML parsing here is intentionally
// minimal for simple key: value pairs.
func readSystemManagedConfig() (orgUUID string, hostUUID string) {
	const systemConfigPath = "/Library/Application Support/run-mcp/config.yaml"
	f, err := os.Open(systemConfigPath)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// split on first ':'
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")
		switch key {
		case "org_uid":
			orgUUID = val
		case "host_uuid":
			hostUUID = val
		}
	}
	if err := scanner.Err(); err != nil {
		logrus.Debugf("error reading system config: %v", err)
	}
	// Validate basic UUID format without forcing version.
	if orgUUID != "" {
		if _, err := uuid.Parse(orgUUID); err != nil {
			logrus.Warn("Invalid org_uuid in system config; ignoring.")
			orgUUID = ""
		}
	}
	if hostUUID != "" {
		if _, err := uuid.Parse(hostUUID); err != nil {
			logrus.Warn("Invalid host_uuid in system config; ignoring.")
			hostUUID = ""
		}
	}
	return orgUUID, hostUUID
}
