package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetector_KnownProviders(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		kind     string
		isSecret bool
	}{
		{"openai_marker", "sk-proj-abcT3BlbkFJdef123456", "OpenAI API Key", true},                                                                             //nolint:gosec,golines // test data
		{"google_AI_prefix", "AIabcdefghijklmnopqrstuvwxyz0123456789", "Google Token", true},                                                                  //nolint:gosec,golines // test data
		{"supabase", "sbp_ab794c03758f962f0ad993b0cd6578b13b4ec407", "Supabase Access Token", true},                                                           //nolint:gosec,golines // test data
		{"aws_access_key", "AKIA1234567890ABCDEF", "AWS Access Key", true},                                                                                    //nolint:gosec,golines // test data
		{"slack_token", "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx", "Slack Token", true},                                                           //nolint:gosec,golines // test data
		{"slack_webhook", "https://hooks.slack.com/services/T1234567/B12345678/abcdefghijklmnopqrstuvwx", "Slack Webhook URL", true},                          //nolint:gosec,golines // test data
		{"database_url", "postgres://user:pass@localhost:5432/db", "Database URL with Credentials", true},                                                     //nolint:gosec,golines // test data
		{"atlassian_url", "https://user:abcdefghijklmnop1234@myteam.atlassian.net/wiki", "Atlassian URL with Credentials", true},                              //nolint:gosec,golines // test data
		{"github_pat", "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", "GitHub Personal Access Token", true}, //nolint:gosec,golines // test data
		{"vantage_token", "vntg_tkn_f299ee3b9b8b9b447f0d9019b87991b5be97cf0f", "Vantage API Token", true},                                                     //nolint:gosec,golines // test data
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, conf, ok := defaultDetector{}.Classify(tc.value)
			if tc.isSecret {
				assert.True(t, ok)
				assert.Equal(t, tc.kind, kind)
				assert.NotEmpty(t, conf)
			} else {
				assert.False(t, ok)
			}
		})
	}
}

func TestDetector_NegativesAndEntropy(t *testing.T) {
	// Clearly not a secret
	_, _, ok := defaultDetector{}.Classify("http://example.com")
	assert.False(t, ok)

	// High-entropy string should trigger generic secret
	val := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef" //nolint:gosec // test data
	kind, conf, ok := defaultDetector{}.Classify(val)
	assert.True(t, ok)
	assert.Equal(t, "Generic Secret", kind)
	assert.Equal(t, "LOW", conf)

	// Too short should not trigger
	_, _, ok = defaultDetector{}.Classify("short-token")
	assert.False(t, ok)
}
