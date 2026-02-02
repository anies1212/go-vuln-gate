// Package output provides formatters for vulnerability scan results.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anies1212/go-vuln-gate/internal/filter"
)

// Format represents the output format type.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat parses a string into a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "text", "":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("unknown format: %s", s)
	}
}

// Formatter formats filter results for output.
type Formatter struct {
	format Format
	writer io.Writer
}

// NewFormatter creates a new Formatter.
func NewFormatter(format Format, w io.Writer) *Formatter {
	return &Formatter{
		format: format,
		writer: w,
	}
}

// Format outputs the filter result in the configured format.
func (f *Formatter) Format(result *filter.FilterResult) error {
	switch f.format {
	case FormatText:
		return f.formatText(result)
	case FormatJSON:
		return f.formatJSON(result)
	case FormatSARIF:
		return f.formatSARIF(result)
	default:
		return fmt.Errorf("unknown format: %s", f.format)
	}
}

func (f *Formatter) formatText(result *filter.FilterResult) error {
	fmt.Fprintf(f.writer, "=== go-vuln-gate Report ===\n\n")
	fmt.Fprintf(f.writer, "Threshold: %.1f (CVSS %s)\n", result.Threshold, result.CVSSVersion)
	if result.MaxAgeYears > 0 {
		fmt.Fprintf(f.writer, "Max age filter: %d years\n", result.MaxAgeYears)
	}
	fmt.Fprintf(f.writer, "Total vulnerabilities found: %d\n", result.TotalVulns)
	fmt.Fprintf(f.writer, "Vulnerabilities above threshold: %d\n", result.FilteredVulns)

	if result.HighestScore > 0 {
		fmt.Fprintf(f.writer, "Highest CVSS score: %.1f (%s)\n", result.HighestScore, filter.GetSeverity(result.HighestScore))
	}

	if len(result.NoCVSSVulns) > 0 {
		fmt.Fprintf(f.writer, "Vulnerabilities without CVSS: %d\n", len(result.NoCVSSVulns))
	}

	if len(result.TooOldVulns) > 0 {
		fmt.Fprintf(f.writer, "Vulnerabilities skipped (too old): %d\n", len(result.TooOldVulns))
	}

	fmt.Fprintf(f.writer, "\n")

	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintf(f.writer, "--- Vulnerabilities Above Threshold ---\n\n")
		for _, vuln := range result.Vulnerabilities {
			f.formatVulnerabilityText(vuln)
		}
	}

	if len(result.NoCVSSVulns) > 0 {
		fmt.Fprintf(f.writer, "--- Vulnerabilities Without CVSS Score ---\n\n")
		for _, vuln := range result.NoCVSSVulns {
			f.formatVulnerabilityText(vuln)
		}
	}

	if result.ShouldFail {
		fmt.Fprintf(f.writer, "\n[FAIL] Found %d vulnerabilities above threshold %.1f\n", result.FilteredVulns, result.Threshold)
		if result.FailOnNoCVSS && len(result.NoCVSSVulns) > 0 {
			fmt.Fprintf(f.writer, "[FAIL] Found %d vulnerabilities without CVSS score (fail-on-no-cvss enabled)\n", len(result.NoCVSSVulns))
		}
	} else {
		fmt.Fprintf(f.writer, "\n[PASS] No vulnerabilities above threshold %.1f\n", result.Threshold)
	}

	return nil
}

func (f *Formatter) formatVulnerabilityText(vuln *filter.VulnerabilityInfo) {
	fmt.Fprintf(f.writer, "  %s\n", vuln.OSVID)

	if len(vuln.CVEIDs) > 0 {
		fmt.Fprintf(f.writer, "    CVE: %s\n", strings.Join(vuln.CVEIDs, ", "))
	}

	if vuln.CVSSScore != nil {
		severity := filter.GetSeverity(vuln.CVSSScore.Score)
		fmt.Fprintf(f.writer, "    CVSS: %.1f (%s, %s)\n", vuln.CVSSScore.Score, severity, vuln.CVSSScore.Version)
	}

	if vuln.Summary != "" {
		fmt.Fprintf(f.writer, "    Summary: %s\n", vuln.Summary)
	}

	if len(vuln.Modules) > 0 {
		fmt.Fprintf(f.writer, "    Affected: %s\n", strings.Join(vuln.Modules, ", "))
	}

	if vuln.FixedVersion != "" {
		fmt.Fprintf(f.writer, "    Fixed in: %s\n", vuln.FixedVersion)
	}

	fmt.Fprintf(f.writer, "\n")
}

// JSONReport represents the JSON output format.
type JSONReport struct {
	Summary         JSONSummary         `json:"summary"`
	Vulnerabilities []JSONVulnerability `json:"vulnerabilities"`
	NoCVSS          []JSONVulnerability `json:"no_cvss,omitempty"`
	TooOld          []JSONVulnerability `json:"too_old,omitempty"`
}

// JSONSummary contains summary statistics.
type JSONSummary struct {
	Threshold     float64 `json:"threshold"`
	CVSSVersion   string  `json:"cvss_version"`
	MaxAgeYears   int     `json:"max_age_years,omitempty"`
	TotalVulns    int     `json:"total_vulnerabilities"`
	FilteredVulns int     `json:"filtered_vulnerabilities"`
	HighestScore  float64 `json:"highest_score"`
	NoCVSSCount   int     `json:"no_cvss_count"`
	TooOldCount   int     `json:"too_old_count,omitempty"`
	ShouldFail    bool    `json:"should_fail"`
}

// JSONVulnerability represents a vulnerability in JSON format.
type JSONVulnerability struct {
	OSVID        string   `json:"osv_id"`
	CVEIDs       []string `json:"cve_ids,omitempty"`
	Summary      string   `json:"summary"`
	CVSSScore    float64  `json:"cvss_score,omitempty"`
	CVSSVersion  string   `json:"cvss_version,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Modules      []string `json:"affected_modules"`
	FixedVersion string   `json:"fixed_version,omitempty"`
}

func (f *Formatter) formatJSON(result *filter.FilterResult) error {
	report := JSONReport{
		Summary: JSONSummary{
			Threshold:     result.Threshold,
			CVSSVersion:   string(result.CVSSVersion),
			MaxAgeYears:   result.MaxAgeYears,
			TotalVulns:    result.TotalVulns,
			FilteredVulns: result.FilteredVulns,
			HighestScore:  result.HighestScore,
			NoCVSSCount:   len(result.NoCVSSVulns),
			TooOldCount:   len(result.TooOldVulns),
			ShouldFail:    result.ShouldFail,
		},
		Vulnerabilities: make([]JSONVulnerability, 0, len(result.Vulnerabilities)),
		NoCVSS:          make([]JSONVulnerability, 0, len(result.NoCVSSVulns)),
		TooOld:          make([]JSONVulnerability, 0, len(result.TooOldVulns)),
	}

	for _, vuln := range result.Vulnerabilities {
		jv := JSONVulnerability{
			OSVID:        vuln.OSVID,
			CVEIDs:       vuln.CVEIDs,
			Summary:      vuln.Summary,
			Modules:      vuln.Modules,
			FixedVersion: vuln.FixedVersion,
		}
		if vuln.CVSSScore != nil {
			jv.CVSSScore = vuln.CVSSScore.Score
			jv.CVSSVersion = string(vuln.CVSSScore.Version)
			jv.Severity = filter.GetSeverity(vuln.CVSSScore.Score).String()
		}
		report.Vulnerabilities = append(report.Vulnerabilities, jv)
	}

	for _, vuln := range result.NoCVSSVulns {
		jv := JSONVulnerability{
			OSVID:        vuln.OSVID,
			CVEIDs:       vuln.CVEIDs,
			Summary:      vuln.Summary,
			Modules:      vuln.Modules,
			FixedVersion: vuln.FixedVersion,
		}
		report.NoCVSS = append(report.NoCVSS, jv)
	}

	for _, vuln := range result.TooOldVulns {
		jv := JSONVulnerability{
			OSVID:        vuln.OSVID,
			CVEIDs:       vuln.CVEIDs,
			Summary:      vuln.Summary,
			Modules:      vuln.Modules,
			FixedVersion: vuln.FixedVersion,
		}
		report.TooOld = append(report.TooOld, jv)
	}

	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SARIFReport represents the SARIF 2.1.0 output format.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in SARIF.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the tool information.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule represents a rule definition.
type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription SARIFMessage           `json:"shortDescription"`
	FullDescription  SARIFMessage           `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents a finding.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation represents a physical location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents an artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a region within a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (f *Formatter) formatSARIF(result *filter.FilterResult) error {
	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "go-vuln-gate",
						Version:        "1.0.0",
						InformationURI: "https://github.com/anies1212/go-vuln-gate",
						Rules:          make([]SARIFRule, 0),
					},
				},
				Results: make([]SARIFResult, 0),
			},
		},
	}

	run := &report.Runs[0]

	allVulns := append(result.Vulnerabilities, result.NoCVSSVulns...)
	for _, vuln := range allVulns {
		rule := SARIFRule{
			ID:   vuln.OSVID,
			Name: vuln.OSVID,
			ShortDescription: SARIFMessage{
				Text: vuln.Summary,
			},
			HelpURI: fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSVID),
		}

		if vuln.CVSSScore != nil {
			rule.Properties = map[string]interface{}{
				"security-severity": fmt.Sprintf("%.1f", vuln.CVSSScore.Score),
			}
		}

		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)

		level := "warning"
		if vuln.CVSSScore != nil {
			switch {
			case vuln.CVSSScore.Score >= 7.0:
				level = "error"
			case vuln.CVSSScore.Score >= 4.0:
				level = "warning"
			default:
				level = "note"
			}
		}

		resultItem := SARIFResult{
			RuleID: vuln.OSVID,
			Level:  level,
			Message: SARIFMessage{
				Text: f.buildSARIFMessage(vuln),
			},
		}

		if vuln.Finding != nil && len(vuln.Finding.Trace) > 0 {
			for _, frame := range vuln.Finding.Trace {
				if frame.Position != nil {
					loc := SARIFLocation{
						PhysicalLocation: &SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: frame.Position.Filename,
							},
							Region: &SARIFRegion{
								StartLine:   frame.Position.Line,
								StartColumn: frame.Position.Column,
							},
						},
					}
					resultItem.Locations = append(resultItem.Locations, loc)
				}
			}
		}

		run.Results = append(run.Results, resultItem)
	}

	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (f *Formatter) buildSARIFMessage(vuln *filter.VulnerabilityInfo) string {
	var parts []string

	parts = append(parts, vuln.Summary)

	if len(vuln.CVEIDs) > 0 {
		parts = append(parts, fmt.Sprintf("CVE: %s", strings.Join(vuln.CVEIDs, ", ")))
	}

	if vuln.CVSSScore != nil {
		parts = append(parts, fmt.Sprintf("CVSS: %.1f (%s)", vuln.CVSSScore.Score, filter.GetSeverity(vuln.CVSSScore.Score)))
	}

	if len(vuln.Modules) > 0 {
		parts = append(parts, fmt.Sprintf("Affected: %s", strings.Join(vuln.Modules, ", ")))
	}

	if vuln.FixedVersion != "" {
		parts = append(parts, fmt.Sprintf("Fixed in: %s", vuln.FixedVersion))
	}

	return strings.Join(parts, ". ")
}
