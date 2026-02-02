package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anies1212/go-vuln-gate/internal/filter"
	"github.com/anies1212/go-vuln-gate/internal/nvd"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
		wantErr  bool
	}{
		{"text", FormatText, false},
		{"TEXT", FormatText, false},
		{"", FormatText, false},
		{"json", FormatJSON, false},
		{"JSON", FormatJSON, false},
		{"sarif", FormatSARIF, false},
		{"SARIF", FormatSARIF, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseFormat(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestFormatter_FormatText(t *testing.T) {
	result := &filter.FilterResult{
		Threshold:     7.0,
		CVSSVersion:   nvd.CVSSVersionV31,
		TotalVulns:    2,
		FilteredVulns: 1,
		HighestScore:  9.8,
		ShouldFail:    true,
		Vulnerabilities: []*filter.VulnerabilityInfo{
			{
				OSVID:   "GO-2024-0001",
				CVEIDs:  []string{"CVE-2024-0001"},
				Summary: "Test vulnerability",
				Modules: []string{"example.com/vuln"},
				CVSSScore: &nvd.CVSSScore{
					CVEID:    "CVE-2024-0001",
					Version:  nvd.CVSSVersionV31,
					Score:    9.8,
					Severity: "CRITICAL",
				},
				FixedVersion: "v1.0.0",
			},
		},
		SkippedVulns: []*filter.VulnerabilityInfo{
			{
				OSVID:   "GO-2024-0002",
				Summary: "Low severity",
				CVSSScore: &nvd.CVSSScore{
					Score: 3.0,
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(FormatText, &buf)
	err := formatter.Format(result)

	require.NoError(t, err)
	output := buf.String()

	assert.Contains(t, output, "go-vuln-gate Report")
	assert.Contains(t, output, "Threshold: 7.0")
	assert.Contains(t, output, "GO-2024-0001")
	assert.Contains(t, output, "CVE-2024-0001")
	assert.Contains(t, output, "9.8")
	assert.Contains(t, output, "CRITICAL")
	assert.Contains(t, output, "[FAIL]")
}

func TestFormatter_FormatJSON(t *testing.T) {
	result := &filter.FilterResult{
		Threshold:     7.0,
		CVSSVersion:   nvd.CVSSVersionV31,
		TotalVulns:    1,
		FilteredVulns: 1,
		HighestScore:  9.8,
		ShouldFail:    true,
		Vulnerabilities: []*filter.VulnerabilityInfo{
			{
				OSVID:   "GO-2024-0001",
				CVEIDs:  []string{"CVE-2024-0001"},
				Summary: "Test vulnerability",
				Modules: []string{"example.com/vuln"},
				CVSSScore: &nvd.CVSSScore{
					CVEID:    "CVE-2024-0001",
					Version:  nvd.CVSSVersionV31,
					Score:    9.8,
					Severity: "CRITICAL",
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(FormatJSON, &buf)
	err := formatter.Format(result)

	require.NoError(t, err)

	var report JSONReport
	err = json.Unmarshal(buf.Bytes(), &report)
	require.NoError(t, err)

	assert.Equal(t, 7.0, report.Summary.Threshold)
	assert.Equal(t, 1, report.Summary.FilteredVulns)
	assert.Equal(t, 9.8, report.Summary.HighestScore)
	assert.True(t, report.Summary.ShouldFail)
	assert.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, "GO-2024-0001", report.Vulnerabilities[0].OSVID)
}

func TestFormatter_FormatSARIF(t *testing.T) {
	result := &filter.FilterResult{
		Threshold:     7.0,
		CVSSVersion:   nvd.CVSSVersionV31,
		TotalVulns:    1,
		FilteredVulns: 1,
		Vulnerabilities: []*filter.VulnerabilityInfo{
			{
				OSVID:   "GO-2024-0001",
				CVEIDs:  []string{"CVE-2024-0001"},
				Summary: "Test vulnerability",
				Modules: []string{"example.com/vuln"},
				CVSSScore: &nvd.CVSSScore{
					Score: 9.8,
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(FormatSARIF, &buf)
	err := formatter.Format(result)

	require.NoError(t, err)

	var report SARIFReport
	err = json.Unmarshal(buf.Bytes(), &report)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", report.Version)
	assert.Len(t, report.Runs, 1)
	assert.Equal(t, "go-vuln-gate", report.Runs[0].Tool.Driver.Name)
	assert.Len(t, report.Runs[0].Results, 1)
	assert.Equal(t, "GO-2024-0001", report.Runs[0].Results[0].RuleID)
	assert.Equal(t, "error", report.Runs[0].Results[0].Level)
}

func TestFormatter_FormatText_Pass(t *testing.T) {
	result := &filter.FilterResult{
		Threshold:     7.0,
		TotalVulns:    1,
		FilteredVulns: 0,
		ShouldFail:    false,
		SkippedVulns: []*filter.VulnerabilityInfo{
			{
				OSVID: "GO-2024-0001",
				CVSSScore: &nvd.CVSSScore{
					Score: 3.0,
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(FormatText, &buf)
	err := formatter.Format(result)

	require.NoError(t, err)
	output := buf.String()

	assert.Contains(t, output, "[PASS]")
	assert.NotContains(t, output, "[FAIL]")
}

func TestFormatter_FormatText_NoCVSS(t *testing.T) {
	result := &filter.FilterResult{
		Threshold:    7.0,
		TotalVulns:   1,
		FailOnNoCVSS: true,
		ShouldFail:   true,
		NoCVSSVulns: []*filter.VulnerabilityInfo{
			{
				OSVID:   "GO-2024-0001",
				Summary: "No CVSS available",
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(FormatText, &buf)
	err := formatter.Format(result)

	require.NoError(t, err)
	output := buf.String()

	assert.Contains(t, output, "Without CVSS Score")
	assert.Contains(t, output, "fail-on-no-cvss")
}
