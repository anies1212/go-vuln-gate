package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected Severity
	}{
		{10.0, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0.0, SeverityNone},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := GetSeverity(tt.score)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatScore(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{9.8, "9.8"},
		{7.0, "7.0"},
		{10.0, "10.0"},
		{0.0, "0.0"},
		{5.55, "5.5"},
		{5.56, "5.6"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatScore(tt.score)
			assert.Equal(t, tt.expected, result)
		})
	}
}
