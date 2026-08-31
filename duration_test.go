package azpim

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
		errMsg   string
	}{
		{
			name:     "go duration",
			value:    "8h",
			expected: "PT8H",
		},
		{
			name:     "mixed units",
			value:    "1h30m",
			expected: "PT1H30M",
		},
		{
			name:     "minutes only",
			value:    "45m",
			expected: "PT45M",
		},
		{
			// Nothing shorter than a minute is a sensible activation, but the
			// renderer must still produce a well-formed span rather than "PT".
			name:     "under a minute",
			value:    "30s",
			expected: "PT30S",
		},
		{
			// Days cannot be expressed as a Go duration, so ISO 8601 has to
			// survive the round trip untouched.
			name:     "iso 8601 passes through",
			value:    "P1D",
			expected: "P1D",
		},
		{
			name:     "iso 8601 is upper cased",
			value:    "pt2h",
			expected: "PT2H",
		},
		{
			name:   "not a duration",
			value:  "eight hours",
			errMsg: "invalid duration",
		},
		{
			name:   "empty",
			value:  "",
			errMsg: "duration is empty",
		},
		{
			name:   "zero",
			value:  "0s",
			errMsg: "must be positive",
		},
		{
			name:   "negative",
			value:  "-1h",
			errMsg: "must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			actual, err := parseDuration(tt.value)

			if tt.errMsg == "" {
				assert.NoError(err)
				assert.Equal(tt.expected, actual)
			} else {
				assert.ErrorContains(err, tt.errMsg)
			}
		})
	}
}

func TestIsoDuration(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("PT8H", isoDuration(8*time.Hour))
	assert.Equal("PT1H1M1S", isoDuration(time.Hour+time.Minute+time.Second))
	assert.Equal("PT0S", isoDuration(0))
	// Sub-second precision is dropped rather than rendered as a fraction.
	assert.Equal("PT1S", isoDuration(1400*time.Millisecond))
}
