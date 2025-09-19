package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindingSet_AddMergeAndList(t *testing.T) {
	set := NewFindingSet()

	f1 := NewSecretFinding("serverA", "OpenAI API Key", "env.OPENAI_API_KEY", "sk-proj-abcT3BlbkFJdef", "HIGH", "/tmp/a.json", 10) //nolint:gosec,golines // test data
	f2 := NewSecretFinding("serverA", "OpenAI API Key", "env.OPENAI_API_KEY", "sk-proj-abcT3BlbkFJdef", "HIGH", "/tmp/a.json", 12)
	f3 := NewSecretFinding("serverB", "OpenAI API Key", "env.OPENAI_API_KEY", "sk-proj-xyzT3BlbkFJuvw", "HIGH", "/tmp/b.json", 5)

	set.Add(f1)
	set.Add(f2) // same value -> should merge lines
	set.Add(f3) // different value -> separate entry

	out := set.ListSorted()
	// Expect two grouped findings
	assert.Len(t, out, 2)

	// Find the merged one and verify lines are deduped & sorted
	var merged SecretFinding
	for _, f := range out {
		if f.ServerName == "serverA" {
			merged = f
		}
	}
	lines := merged.Occurrences["/tmp/a.json"]
	assert.Equal(t, []int{10, 12}, lines)
}

func TestLocateLines(t *testing.T) {
	content := []byte("line1\nsecret_here\nother line\nsecret_here again")
	lines := locateLines(content, "secret_here")
	assert.Equal(t, []int{2, 4}, lines)
}
