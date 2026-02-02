// Package govulncheck provides a wrapper for running govulncheck and parsing its JSON output.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Message represents a single JSON line from govulncheck output.
type Message struct {
	Config   *Config   `json:"config,omitempty"`
	Progress *Progress `json:"progress,omitempty"`
	OSV      *OSV      `json:"osv,omitempty"`
	Finding  *Finding  `json:"finding,omitempty"`
}

// Config contains the scan configuration.
type Config struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
	DB              string `json:"db"`
	DBLastModified  string `json:"db_last_modified"`
	GoVersion       string `json:"go_version"`
	ScanLevel       string `json:"scan_level"`
}

// Progress contains progress information during scanning.
type Progress struct {
	Message string `json:"message"`
}

// OSV represents a vulnerability in OSV format.
type OSV struct {
	SchemaVersion    string            `json:"schema_version"`
	ID               string            `json:"id"`
	Modified         string            `json:"modified"`
	Published        string            `json:"published"`
	Aliases          []string          `json:"aliases"`
	Summary          string            `json:"summary"`
	Details          string            `json:"details"`
	Affected         []Affected        `json:"affected"`
	References       []Reference       `json:"references"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

// Affected describes an affected package.
type Affected struct {
	Package           Package            `json:"package"`
	Ranges            []Range            `json:"ranges"`
	EcosystemSpecific *EcosystemSpecific `json:"ecosystem_specific,omitempty"`
}

// Package identifies the affected package.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Range describes the affected version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event represents a version event (introduced or fixed).
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// EcosystemSpecific contains Go-specific information.
type EcosystemSpecific struct {
	Imports []Import `json:"imports,omitempty"`
}

// Import describes an affected import path.
type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

// Reference contains a reference link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// DatabaseSpecific contains database-specific metadata.
type DatabaseSpecific struct {
	URL          string `json:"url,omitempty"`
	ReviewStatus string `json:"review_status,omitempty"`
}

// Finding represents a discovered vulnerability in the scanned code.
type Finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	Trace        []Frame `json:"trace"`
}

// Frame represents a call stack frame.
type Frame struct {
	Module   string    `json:"module,omitempty"`
	Version  string    `json:"version,omitempty"`
	Package  string    `json:"package,omitempty"`
	Function string    `json:"function,omitempty"`
	Receiver string    `json:"receiver,omitempty"`
	Position *Position `json:"position,omitempty"`
}

// Position represents a source code location.
type Position struct {
	Filename string `json:"filename"`
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// Result contains the parsed govulncheck output.
type Result struct {
	Config   *Config
	OSVs     map[string]*OSV
	Findings []*Finding
}

// Runner executes govulncheck and parses its output.
type Runner struct {
	govulncheckPath string
}

// NewRunner creates a new Runner with default settings.
func NewRunner() *Runner {
	return &Runner{
		govulncheckPath: "govulncheck",
	}
}

// Run executes govulncheck on the target path and returns parsed results.
func (r *Runner) Run(ctx context.Context, targetPath string) (*Result, error) {
	args := []string{"-format", "json"}
	if targetPath != "" {
		args = append(args, targetPath)
	} else {
		args = append(args, "./...")
	}

	cmd := exec.CommandContext(ctx, r.govulncheckPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// govulncheck returns exit code 3 when vulnerabilities are found
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 3 {
				stderrStr := stderr.String()
				// Provide helpful message for common errors
				if strings.Contains(stderrStr, "package") && strings.Contains(stderrStr, "without types") {
					return nil, fmt.Errorf("govulncheck failed: %w\nstderr: %s\n\nThis error often occurs due to dependency resolution issues. Try:\n1. Run 'go mod tidy' to clean up dependencies\n2. Run 'go mod download' to fetch all dependencies\n3. Ensure your Go version matches the project requirements", err, stderrStr)
				}
				return nil, fmt.Errorf("govulncheck failed: %w\nstderr: %s", err, stderrStr)
			}
		} else {
			return nil, fmt.Errorf("failed to run govulncheck: %w", err)
		}
	}

	return r.parseOutput(stdout.Bytes())
}

// parseOutput parses the streaming JSON output from govulncheck.
// govulncheck outputs multiple JSON objects (not JSON Lines), so we use json.Decoder
// to handle the stream of objects.
func (r *Runner) parseOutput(data []byte) (*Result, error) {
	result := &Result{
		OSVs:     make(map[string]*OSV),
		Findings: make([]*Finding, 0),
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		if msg.Config != nil {
			result.Config = msg.Config
		}
		if msg.OSV != nil {
			result.OSVs[msg.OSV.ID] = msg.OSV
		}
		if msg.Finding != nil {
			result.Findings = append(result.Findings, msg.Finding)
		}
	}

	return result, nil
}

// GetCVEIDs extracts CVE IDs from the OSV aliases.
func (o *OSV) GetCVEIDs() []string {
	var cveIDs []string
	for _, alias := range o.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveIDs = append(cveIDs, alias)
		}
	}
	return cveIDs
}

// GetAffectedModules returns the list of affected module names.
func (o *OSV) GetAffectedModules() []string {
	modules := make([]string, 0, len(o.Affected))
	for _, affected := range o.Affected {
		modules = append(modules, affected.Package.Name)
	}
	return modules
}
