package scanner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSecret_EdgeCases(t *testing.T) {
	// Empty
	assert.Empty(t, redactSecret(""))

	// Short strings (<= 8) become fully masked
	assert.Equal(t, strings.Repeat("*", 3), redactSecret("abc"))
	assert.Equal(t, strings.Repeat("*", 8), redactSecret("abcdefgh"))

	// Length 9..16 keeps first 4 chars, masks the rest
	out9 := redactSecret("abcdefghi")
	assert.Equal(t, "abcd*****", out9)

	out16 := redactSecret("abcdefghijklmnop")
	assert.Equal(t, "abcd************", out16)

	// Longer than 16 gets ellipsis and fixed mask length (12 stars)
	outLong := redactSecret("abcdefghijklmnopqrstuvwxyz0123456789")
	assert.True(t, strings.HasPrefix(outLong, "abcd"))
	assert.True(t, strings.HasSuffix(outLong, "..."))
	// Between prefix and ellipsis should be 12 asterisks
	mid := strings.TrimPrefix(outLong, "abcd")
	mid = strings.TrimSuffix(mid, "...")
	assert.Equal(t, strings.Repeat("*", 12), mid)
}
