// Package vulndb provides a client for the Go Vulnerability Database API.
package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://vuln.go.dev"
	defaultTimeout = 30 * time.Second
)

// OSVEntry represents an entry from the Go Vulnerability Database.
type OSVEntry struct {
	SchemaVersion    string            `json:"schema_version"`
	ID               string            `json:"id"`
	Modified         string            `json:"modified"`
	Published        string            `json:"published"`
	Aliases          []string          `json:"aliases"`
	Summary          string            `json:"summary"`
	Details          string            `json:"details"`
	Affected         []Affected        `json:"affected"`
	References       []Reference       `json:"references"`
	Credits          []Credit          `json:"credits,omitempty"`
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

// EcosystemSpecific contains ecosystem-specific information.
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

// Credit represents a credit entry.
type Credit struct {
	Name string `json:"name"`
}

// DatabaseSpecific contains database-specific metadata.
type DatabaseSpecific struct {
	URL          string `json:"url,omitempty"`
	ReviewStatus string `json:"review_status,omitempty"`
}

// Client is a Go Vulnerability Database API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	cache      map[string]*OSVEntry
	cacheMu    sync.RWMutex
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithBaseURL sets the base URL for the API.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = strings.TrimSuffix(url, "/")
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// NewClient creates a new Client with the given options.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		cache: make(map[string]*OSVEntry),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetOSV fetches an OSV entry by its ID.
func (c *Client) GetOSV(ctx context.Context, osvID string) (*OSVEntry, error) {
	// Check cache
	c.cacheMu.RLock()
	if entry, ok := c.cache[osvID]; ok {
		c.cacheMu.RUnlock()
		return entry, nil
	}
	c.cacheMu.RUnlock()

	// Fetch from API
	url := fmt.Sprintf("%s/ID/%s.json", c.baseURL, osvID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OSV entry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("OSV entry not found: %s", osvID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var entry OSVEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse OSV entry: %w", err)
	}

	// Store in cache
	c.cacheMu.Lock()
	c.cache[osvID] = &entry
	c.cacheMu.Unlock()

	return &entry, nil
}

// GetCVEIDs fetches CVE IDs for a given OSV ID.
func (c *Client) GetCVEIDs(ctx context.Context, osvID string) ([]string, error) {
	entry, err := c.GetOSV(ctx, osvID)
	if err != nil {
		return nil, err
	}

	return entry.GetCVEIDs(), nil
}

// GetCVEIDs extracts CVE IDs from the entry's aliases.
func (e *OSVEntry) GetCVEIDs() []string {
	var cveIDs []string
	for _, alias := range e.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveIDs = append(cveIDs, alias)
		}
	}
	return cveIDs
}

// GetGHSAIDs extracts GHSA IDs from the entry's aliases.
func (e *OSVEntry) GetGHSAIDs() []string {
	var ghsaIDs []string
	for _, alias := range e.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			ghsaIDs = append(ghsaIDs, alias)
		}
	}
	return ghsaIDs
}
