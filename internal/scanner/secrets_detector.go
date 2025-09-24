package scanner

import (
	"math"
	"regexp"
	"strings"
)

// Provider regexes and display names with deterministic order.
//
//nolint:gochecknoglobals,golines // Static registries used for token detection across package.
var (
	providerTokenRegex = map[string]*regexp.Regexp{
		"openai":        regexp.MustCompile(`\b(?:sk-[A-Za-z0-9]{48}|sk-[A-Za-z0-9_-]+T3BlbkFJ[A-Za-z0-9_-]+)\b`),
		"anthropic":     regexp.MustCompile(`\bsk-ant-api\d{0,2}-[A-Za-z0-9\-]{80,120}\b`),
		"google":        regexp.MustCompile(`\b(?:AIza[0-9A-Za-z\-_]{35}|AIzaSy[A-Za-z0-9\-_]{33}|AI[a-zA-Z0-9_\-]{30,})\b`),
		"openrouter":    regexp.MustCompile(`\bsk-or-v1-[a-z0-9]{64}\b`),
		"groq":          regexp.MustCompile(`\bgsk_[A-Za-z0-9]{20,}\b`),
		"mistral":       regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`),
		"elevenlabs":    regexp.MustCompile(`\b(?:[a-z0-9]{32}|sk_[a-z0-9]{48})\b`),
		"supabase":      regexp.MustCompile(`\bsbp_[a-f0-9]{40}\b`),
		"deepseek":      regexp.MustCompile(`\bsk-[a-f0-9]{32}\b`),
		"xai":           regexp.MustCompile(`\bxai-[A-Za-z0-9]{80}\b`),
		"aws":           regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"database_url":  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^:]+:([^@]+)@[^/\s]+`),
		"slack":         regexp.MustCompile(`\b(?:xoxb-\d{10,}-\d{10,}-[A-Za-z0-9]{24,}|xoxp-\d{10,}-\d{10,}-\d{10,}-[A-Za-z0-9]{24,}|xoxa-2-\d{10,}-\d{10,}-\d{10,}-[A-Za-z0-9]{32,}|xoxs-[A-Za-z0-9-]{20,}|xapp-1-[A-Za-z0-9]{8,}-\d{10,}-[A-Za-z0-9]{32,}|xoxe-1-[A-Za-z0-9-]{32,})\b`),
		"slack_webhook": regexp.MustCompile(`^https://hooks\.slack\.com/services/T[A-Z0-9]{7,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}$`),
		"atlassian":     regexp.MustCompile(`\b(?:Atlassian\s+API\s+Token|atlassian[-_ ]?api[-_ ]?token)\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:[A-Za-z0-9]{24}\b`),
		"atlassian_url": regexp.MustCompile(`(?i)\bhttps?://[^:@\s]+:[A-Za-z0-9]{16,64}@[A-Za-z0-9.-]+\.atlassian\.net\S*\b`),
		"github_pat":    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
		"vantage":       regexp.MustCompile(`\bvntg_tkn_[a-f0-9]{40}\b`),
	}
	providerDisplayType = map[string]string{
		"openai":        "OpenAI API Key",
		"anthropic":     "Anthropic API Key",
		"google":        "Google Token",
		"openrouter":    "OpenRouter API Key",
		"groq":          "Groq API Key",
		"mistral":       "Mistral API Key",
		"elevenlabs":    "ElevenLabs API Key",
		"supabase":      "Supabase Access Token",
		"deepseek":      "DeepSeek API Key",
		"xai":           "xAI API Key",
		"aws":           "AWS Access Key",
		"database_url":  "Database URL with Credentials",
		"slack":         "Slack Token",
		"slack_webhook": "Slack Webhook URL",
		"atlassian":     "Atlassian API Token",
		"atlassian_url": "Atlassian URL with Credentials",
		"github_pat":    "GitHub Personal Access Token",
		"vantage":       "Vantage API Token",
	}
	providerOrder = []string{
		"openai", "anthropic", "google", "openrouter", "groq",
		"mistral", "elevenlabs", "supabase", "deepseek", "xai",
		"aws", "database_url", "github_pat", "vantage", "slack",
		"slack_webhook", "atlassian", "atlassian_url",
	}
)

// Detector classifies whether a string looks like a secret and returns its kind and confidence.
type Detector interface {
	Classify(value string) (kind, confidence string, secretFound bool)
}

type defaultDetector struct{}

func (d defaultDetector) Classify(value string) (string, string, bool) {
	return classifySecretValue(value)
}

func classifySecretValue(s string) (string, string, bool) {
	for _, provider := range providerOrder {
		re := providerTokenRegex[provider]
		if re != nil && re.MatchString(s) {
			return providerDisplayType[provider], "HIGH", true
		}
	}
	if isHighEntropy(s) {
		return "Generic Secret", "LOW", true
	}
	return "", "", false
}

func isHighEntropy(s string) bool {
	const minLen = 24
	const minEntropyBitsPerChar = 3.8
	if len(s) < minLen {
		return false
	}
	if strings.HasPrefix(s, "-") {
		return false
	}
	if strings.ContainsAny(s, "@/=") {
		return false
	}
	if strings.Contains(strings.ToLower(s), "http") {
		return false
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	h := shannonEntropy(s)
	return h >= minEntropyBitsPerChar
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ { //nolint:intrange // keep explicit index for clarity
		b := s[i]
		const asciiThreshold = 128
		if b < asciiThreshold {
			freq[b]++
		}
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}
