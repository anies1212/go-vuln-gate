// Package filter provides CVSS score-based filtering for vulnerabilities.
package filter

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/anies1212/go-vuln-gate/internal/govulncheck"
	"github.com/anies1212/go-vuln-gate/internal/nvd"
)

// VulnerabilityInfo aggregates vulnerability data from multiple sources.
type VulnerabilityInfo struct {
	OSVID        string
	CVEIDs       []string
	Summary      string
	Details      string
	CVSSScore    *nvd.CVSSScore
	Modules      []string
	FixedVersion string
	Finding      *govulncheck.Finding
	OSV          *govulncheck.OSV
	Published    time.Time
}

// FilterResult contains the results of vulnerability filtering.
type FilterResult struct {
	Threshold       float64
	CVSSVersion     nvd.CVSSVersion
	MaxAgeYears     int
	TotalVulns      int
	FilteredVulns   int
	HighestScore    float64
	Vulnerabilities []*VulnerabilityInfo
	NoCVSSVulns     []*VulnerabilityInfo
	SkippedVulns    []*VulnerabilityInfo
	TooOldVulns     []*VulnerabilityInfo
	FailOnNoCVSS    bool
	ShouldFail      bool
}

// Filter applies CVSS score filtering to vulnerabilities.
type Filter struct {
	nvdClient    *nvd.Client
	threshold    float64
	cvssVersion  nvd.CVSSVersion
	failOnNoCVSS bool
	maxAgeYears  int
	calledOnly   bool
}

// FilterOption configures the Filter.
type FilterOption func(*Filter)

// WithThreshold sets the CVSS score threshold.
func WithThreshold(threshold float64) FilterOption {
	return func(f *Filter) {
		f.threshold = threshold
	}
}

// WithCVSSVersion sets the preferred CVSS version.
func WithCVSSVersion(version nvd.CVSSVersion) FilterOption {
	return func(f *Filter) {
		f.cvssVersion = version
	}
}

// WithFailOnNoCVSS configures whether to fail when CVSS score is unavailable.
func WithFailOnNoCVSS(fail bool) FilterOption {
	return func(f *Filter) {
		f.failOnNoCVSS = fail
	}
}

// WithMaxAgeYears sets the maximum age filter in years (0 = no limit).
func WithMaxAgeYears(years int) FilterOption {
	return func(f *Filter) {
		f.maxAgeYears = years
	}
}

// WithCalledOnly filters to only include vulnerabilities that are actually called.
func WithCalledOnly(called bool) FilterOption {
	return func(f *Filter) {
		f.calledOnly = called
	}
}

// NewFilter creates a new Filter with the given options.
func NewFilter(nvdClient *nvd.Client, opts ...FilterOption) *Filter {
	f := &Filter{
		nvdClient:    nvdClient,
		threshold:    7.0,
		cvssVersion:  nvd.CVSSVersionV31,
		failOnNoCVSS: false,
		maxAgeYears:  0,
		calledOnly:   true, // Default: only check vulnerabilities that are actually called
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// Apply filters vulnerabilities based on CVSS scores.
func (f *Filter) Apply(ctx context.Context, result *govulncheck.Result) (*FilterResult, error) {
	filterResult := &FilterResult{
		Threshold:       f.threshold,
		CVSSVersion:     f.cvssVersion,
		MaxAgeYears:     f.maxAgeYears,
		FailOnNoCVSS:    f.failOnNoCVSS,
		Vulnerabilities: make([]*VulnerabilityInfo, 0),
		NoCVSSVulns:     make([]*VulnerabilityInfo, 0),
		SkippedVulns:    make([]*VulnerabilityInfo, 0),
		TooOldVulns:     make([]*VulnerabilityInfo, 0),
	}

	findingsByOSV := make(map[string]*govulncheck.Finding)
	for _, finding := range result.Findings {
		findingsByOSV[finding.OSV] = finding
	}

	var cutoffDate time.Time
	if f.maxAgeYears > 0 {
		cutoffDate = time.Now().AddDate(-f.maxAgeYears, 0, 0)
	}

	type osvInfo struct {
		osvID   string
		osv     *govulncheck.OSV
		finding *govulncheck.Finding
		cveID   string
	}

	var toFetch []osvInfo
	var noCVEVulns []*VulnerabilityInfo

	for osvID, osv := range result.OSVs {
		finding := findingsByOSV[osvID]

		// Skip vulnerabilities without findings if calledOnly is enabled
		if f.calledOnly && finding == nil {
			continue
		}

		published, _ := parseOSVDate(osv.Published)

		vulnInfo := &VulnerabilityInfo{
			OSVID:     osvID,
			CVEIDs:    osv.GetCVEIDs(),
			Summary:   osv.Summary,
			Details:   osv.Details,
			Modules:   osv.GetAffectedModules(),
			Finding:   finding,
			OSV:       osv,
			Published: published,
		}

		if finding != nil {
			vulnInfo.FixedVersion = finding.FixedVersion
		}

		// Apply age filter
		if f.maxAgeYears > 0 && !published.IsZero() && published.Before(cutoffDate) {
			filterResult.TooOldVulns = append(filterResult.TooOldVulns, vulnInfo)
			continue
		}

		filterResult.TotalVulns++

		if len(vulnInfo.CVEIDs) > 0 {
			toFetch = append(toFetch, osvInfo{
				osvID:   osvID,
				osv:     osv,
				finding: finding,
				cveID:   vulnInfo.CVEIDs[0],
			})
		} else {
			noCVEVulns = append(noCVEVulns, vulnInfo)
		}
	}

	filterResult.NoCVSSVulns = append(filterResult.NoCVSSVulns, noCVEVulns...)

	// Fetch CVSS scores concurrently
	if len(toFetch) > 0 {
		requests := make([]nvd.BulkFetchRequest, len(toFetch))
		for i, info := range toFetch {
			requests[i] = nvd.BulkFetchRequest{
				CVEID:            info.cveID,
				PreferredVersion: f.cvssVersion,
			}
		}

		results := f.nvdClient.BulkGetCVSSScores(ctx, requests)

		for i, fetchResult := range results {
			info := toFetch[i]
			published, _ := parseOSVDate(info.osv.Published)

			vulnInfo := &VulnerabilityInfo{
				OSVID:     info.osvID,
				CVEIDs:    info.osv.GetCVEIDs(),
				Summary:   info.osv.Summary,
				Details:   info.osv.Details,
				Modules:   info.osv.GetAffectedModules(),
				Finding:   info.finding,
				OSV:       info.osv,
				Published: published,
			}

			if info.finding != nil {
				vulnInfo.FixedVersion = info.finding.FixedVersion
			}

			if fetchResult.Error != nil {
				filterResult.NoCVSSVulns = append(filterResult.NoCVSSVulns, vulnInfo)
				continue
			}

			vulnInfo.CVSSScore = fetchResult.Score

			if vulnInfo.CVSSScore.Score >= f.threshold {
				filterResult.Vulnerabilities = append(filterResult.Vulnerabilities, vulnInfo)
				filterResult.FilteredVulns++

				if vulnInfo.CVSSScore.Score > filterResult.HighestScore {
					filterResult.HighestScore = vulnInfo.CVSSScore.Score
				}
			} else {
				filterResult.SkippedVulns = append(filterResult.SkippedVulns, vulnInfo)
			}
		}
	}

	// Sort by score descending using slices package
	slices.SortFunc(filterResult.Vulnerabilities, func(a, b *VulnerabilityInfo) int {
		return cmp.Compare(b.CVSSScore.Score, a.CVSSScore.Score)
	})

	filterResult.ShouldFail = filterResult.FilteredVulns > 0
	if f.failOnNoCVSS && len(filterResult.NoCVSSVulns) > 0 {
		filterResult.ShouldFail = true
	}

	return filterResult, nil
}

// parseOSVDate parses an OSV-format date string.
func parseOSVDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("failed to parse date: %s", dateStr)
}

// Severity represents CVSS severity levels.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// GetSeverity returns the severity level for a CVSS score.
func GetSeverity(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// FormatScore formats a CVSS score for display.
func FormatScore(score float64) string {
	return fmt.Sprintf("%.1f", score)
}
