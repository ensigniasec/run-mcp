package scanner

import (
	"bytes"
	"strings"
)

type Redactor func(string) string

func redactSecret(secret string) string {
	n := len(secret)
	if n == 0 {
		return ""
	}
	const maxMaskLen = 16
	const prefixPeek = 4
	if n <= prefixPeek+4 {
		return strings.Repeat("*", n)
	}
	if n > maxMaskLen {
		return secret[:prefixPeek] + strings.Repeat("*", maxMaskLen-prefixPeek) + "..."
	}
	return secret[:prefixPeek] + strings.Repeat("*", n-prefixPeek)
}

func (c *secretScanContext) handleString(dotPath, s string) interface{} {
	if s == "" {
		return s
	}
	secretKind, confidence, secretFound := c.detector.Classify(s)
	if secretFound {
		redacted := c.redactor(s)
		lines := locateLines(c.originalFileContent, s)
		finding := NewSecretFinding(c.currentServer, secretKind, dotPath, s, confidence, c.filePath, 0)
		if len(lines) > 0 {
			finding.Occurrences[c.filePath] = lines
		}
		c.findings.Add(finding)
		c.fileContent = bytes.ReplaceAll(c.fileContent, []byte(s), []byte(redacted))
		return redacted
	}
	return s
}
