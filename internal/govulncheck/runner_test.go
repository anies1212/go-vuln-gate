package govulncheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOutput(t *testing.T) {
	input := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.0.0","db":"https://vuln.go.dev","go_version":"go1.21.0","scan_level":"symbol"}}
{"progress":{"message":"Scanning your code and 123 packages..."}}
{"osv":{"schema_version":"1.3.1","id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","published":"2024-01-01T00:00:00Z","aliases":["CVE-2024-0001","GHSA-xxxx-xxxx-xxxx"],"summary":"Test vulnerability","details":"This is a test vulnerability","affected":[{"package":{"name":"example.com/vuln","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}}
{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.0.0","trace":[{"module":"example.com/vuln","version":"v0.9.0","package":"example.com/vuln","function":"VulnFunc"}]}}`

	runner := NewRunner()
	result, err := runner.parseOutput([]byte(input))

	require.NoError(t, err)
	assert.NotNil(t, result.Config)
	assert.Equal(t, "govulncheck", result.Config.ScannerName)
	assert.Len(t, result.OSVs, 1)
	assert.Len(t, result.Findings, 1)

	osv := result.OSVs["GO-2024-0001"]
	assert.Equal(t, "GO-2024-0001", osv.ID)
	assert.Equal(t, "Test vulnerability", osv.Summary)
	assert.Equal(t, []string{"CVE-2024-0001", "GHSA-xxxx-xxxx-xxxx"}, osv.Aliases)

	finding := result.Findings[0]
	assert.Equal(t, "GO-2024-0001", finding.OSV)
	assert.Equal(t, "v1.0.0", finding.FixedVersion)
}

func TestOSV_GetCVEIDs(t *testing.T) {
	tests := []struct {
		name     string
		aliases  []string
		expected []string
	}{
		{
			name:     "single CVE",
			aliases:  []string{"CVE-2024-0001"},
			expected: []string{"CVE-2024-0001"},
		},
		{
			name:     "multiple CVEs",
			aliases:  []string{"CVE-2024-0001", "CVE-2024-0002"},
			expected: []string{"CVE-2024-0001", "CVE-2024-0002"},
		},
		{
			name:     "mixed aliases",
			aliases:  []string{"CVE-2024-0001", "GHSA-xxxx-xxxx-xxxx"},
			expected: []string{"CVE-2024-0001"},
		},
		{
			name:     "no CVE",
			aliases:  []string{"GHSA-xxxx-xxxx-xxxx"},
			expected: nil,
		},
		{
			name:     "empty",
			aliases:  []string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osv := &OSV{Aliases: tt.aliases}
			result := osv.GetCVEIDs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOSV_GetAffectedModules(t *testing.T) {
	osv := &OSV{
		Affected: []Affected{
			{Package: Package{Name: "example.com/pkg1", Ecosystem: "Go"}},
			{Package: Package{Name: "example.com/pkg2", Ecosystem: "Go"}},
		},
	}

	modules := osv.GetAffectedModules()
	assert.Equal(t, []string{"example.com/pkg1", "example.com/pkg2"}, modules)
}

func TestParseOutput_EmptyInput(t *testing.T) {
	runner := NewRunner()
	result, err := runner.parseOutput([]byte(""))

	require.NoError(t, err)
	assert.Nil(t, result.Config)
	assert.Empty(t, result.OSVs)
	assert.Empty(t, result.Findings)
}

func TestParseOutput_InvalidJSON(t *testing.T) {
	runner := NewRunner()
	_, err := runner.parseOutput([]byte("invalid json"))

	assert.Error(t, err)
}

func TestParseOutput_PrettyPrintedJSON(t *testing.T) {
	// Test with pretty-printed JSON (multi-line format from newer govulncheck versions)
	input := `{
  "config": {
    "protocol_version": "v1.0.0",
    "scanner_name": "govulncheck",
    "scanner_version": "v1.1.4",
    "db": "https://vuln.go.dev",
    "go_version": "go1.21.0",
    "scan_level": "symbol"
  }
}
{
  "osv": {
    "schema_version": "1.3.1",
    "id": "GO-2024-0001",
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2024-0001"],
    "summary": "Test vulnerability",
    "details": "This is a test vulnerability",
    "affected": [
      {
        "package": {
          "name": "example.com/vuln",
          "ecosystem": "Go"
        },
        "ranges": [
          {
            "type": "SEMVER",
            "events": [
              {"introduced": "0"},
              {"fixed": "1.0.0"}
            ]
          }
        ]
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "fixed_version": "v1.0.0",
    "trace": [
      {
        "module": "example.com/vuln",
        "version": "v0.9.0",
        "package": "example.com/vuln",
        "function": "VulnFunc"
      }
    ]
  }
}`

	runner := NewRunner()
	result, err := runner.parseOutput([]byte(input))

	require.NoError(t, err)
	assert.NotNil(t, result.Config)
	assert.Equal(t, "govulncheck", result.Config.ScannerName)
	assert.Equal(t, "v1.1.4", result.Config.ScannerVersion)
	assert.Len(t, result.OSVs, 1)
	assert.Len(t, result.Findings, 1)

	osv := result.OSVs["GO-2024-0001"]
	assert.Equal(t, "GO-2024-0001", osv.ID)
	assert.Equal(t, "Test vulnerability", osv.Summary)
}
