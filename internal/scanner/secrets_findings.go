package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// SecretFinding represents a detected secret.
type SecretFinding struct {
	Kind        string           `json:"kind"`
	Key         string           `json:"key"`
	Value       string           `json:"value"` // Redacted value
	Occurrences map[string][]int `json:"occurrences"`
	ValueHash   string           `json:"value_hash,omitempty"`
	ServerName  string           `json:"server_name"`
	Confidence  string           `json:"confidence"`
}

// NewSecretFinding constructs a SecretFinding with automatic value redaction.
// filePath is recorded for occurrences; pass line > 0 to record a single line.
func NewSecretFinding(
	serverName, secretKind, key, rawValue, confidence string,
	filePath string, line int,
) SecretFinding {
	var sf SecretFinding
	sf.Kind = secretKind
	sf.Key = key
	// Redact the secret right away, but keep a hash of the raw value for grouping.
	sf.Value = redactSecret(rawValue)
	h := sha256.Sum256([]byte(rawValue))
	sf.ValueHash = hex.EncodeToString(h[:])
	sf.ServerName = serverName
	sf.Confidence = confidence
	sf.Occurrences = make(map[string][]int, 1)
	sf.Occurrences[filePath] = []int{line}
	return sf
}

// FindingSet aggregates secret findings by the hash of their raw values,
// merges occurrences, and can produce a deterministic, normalized list.
type FindingSet struct {
	byHash map[string]*SecretFinding
}

func NewFindingSet() *FindingSet {
	return &FindingSet{byHash: make(map[string]*SecretFinding)}
}

// Add merges the incoming finding into the set, grouping by ValueHash and
// aggregating occurrences. The caller is responsible for setting ValueHash.
func (s *FindingSet) Add(incoming SecretFinding) {
	if existing, ok := s.byHash[incoming.ValueHash]; ok {
		for file, lines := range incoming.Occurrences {
			existing.Occurrences[file] = append(existing.Occurrences[file], lines...)
		}
		return
	}
	f := incoming
	s.byHash[incoming.ValueHash] = &f
}

// ListSorted returns a copy of all findings with de-duplicated, sorted line
// occurrences per file, ordered deterministically for stable output and tests.
func (s *FindingSet) ListSorted() []SecretFinding {
	out := make([]SecretFinding, 0, len(s.byHash))
	for _, f := range s.byHash {
		for file, lines := range f.Occurrences {
			f.Occurrences[file] = dedupeAndSortLines(lines)
		}
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return compareFindings(out[i], out[j]) })
	return out
}

// compareFindings defines deterministic ordering for findings to stabilize
// output and tests. Ordering precedence: ServerName, Kind, Key, ValueHash.
func compareFindings(a, b SecretFinding) bool {
	if a.ServerName != b.ServerName {
		return a.ServerName < b.ServerName
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Key != b.Key {
		return a.Key < b.Key
	}
	return a.ValueHash < b.ValueHash
}

// dedupeAndSortLines returns a copy of lines with duplicates removed and values sorted ascending.
func dedupeAndSortLines(lines []int) []int {
	if len(lines) <= 1 {
		return lines
	}
	seen := make(map[int]struct{}, len(lines))
	unique := make([]int, 0, len(lines))
	for _, ln := range lines {
		if _, ok := seen[ln]; ok {
			continue
		}
		seen[ln] = struct{}{}
		unique = append(unique, ln)
	}
	sort.Ints(unique)
	return unique
}

// locateLines returns all 1-based line numbers where token appears in content.
func locateLines(content []byte, token string) []int {
	if token == "" || len(content) == 0 {
		return nil
	}
	var lines []int
	start := 0
	lineNum := 1
	for i := 0; i <= len(content); i++ {
		if i == len(content) || content[i] == '\n' {
			line := string(content[start:i])
			if strings.Contains(line, token) {
				lines = append(lines, lineNum)
			}
			start = i + 1
			lineNum++
		}
	}
	return lines
}

// Findings returns the aggregated, deterministic list of secret findings.
func (c *secretScanContext) Findings() []SecretFinding {
	return c.findings.ListSorted()
}
