// Package nvd provides a client for the NVD (National Vulnerability Database) API 2.0.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

const (
	defaultBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultTimeout        = 30 * time.Second
	rateLimitWithKey      = 600 * time.Millisecond
	rateLimitWithoutKey   = 6 * time.Second
	maxRetries            = 3
	baseBackoff           = 10 * time.Second
	maxBackoff            = 60 * time.Second
	defaultConcurrency    = 5
	concurrencyWithoutKey = 1
)

// CVSSVersion represents the CVSS version to use for scoring.
type CVSSVersion string

const (
	CVSSVersionV2  CVSSVersion = "v2"
	CVSSVersionV3  CVSSVersion = "v3"
	CVSSVersionV31 CVSSVersion = "v31"
	CVSSVersionV4  CVSSVersion = "v4"
)

// ErrRateLimited is returned when the NVD API rate limit is exceeded.
var ErrRateLimited = errors.New("rate limited by NVD API")

// CVEResponse represents the response from the NVD API.
type CVEResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a vulnerability entry in the NVD response.
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// CVE represents the CVE data structure.
type CVE struct {
	ID               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        string        `json:"published"`
	LastModified     string        `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	Descriptions     []Description `json:"descriptions"`
	Metrics          Metrics       `json:"metrics"`
	References       []Reference   `json:"references"`
}

// Description represents a CVE description.
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics contains all CVSS metrics for a CVE.
type Metrics struct {
	CVSSMetricV40 []CVSSMetricV4  `json:"cvssMetricV40,omitempty"`
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV30 []CVSSMetricV3  `json:"cvssMetricV30,omitempty"`
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
}

// CVSSMetricV4 represents CVSS v4.0 metric data.
type CVSSMetricV4 struct {
	Source   string     `json:"source"`
	Type     string     `json:"type"`
	CVSSData CVSSDataV4 `json:"cvssData"`
}

// CVSSDataV4 represents CVSS v4.0 scoring data.
type CVSSDataV4 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CVSSMetricV31 represents CVSS v3.1 metric data.
type CVSSMetricV31 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSDataV3 `json:"cvssData"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
}

// CVSSMetricV3 represents CVSS v3.0 metric data.
type CVSSMetricV3 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSDataV3 `json:"cvssData"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
}

// CVSSDataV3 represents CVSS v3.x scoring data.
type CVSSDataV3 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CVSSMetricV2 represents CVSS v2.0 metric data.
type CVSSMetricV2 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSDataV2 `json:"cvssData"`
	BaseSeverity        string     `json:"baseSeverity"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
}

// CVSSDataV2 represents CVSS v2.0 scoring data.
type CVSSDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

// Reference represents a reference link for a CVE.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// CVSSScore holds the extracted CVSS score information.
type CVSSScore struct {
	CVEID        string
	Version      CVSSVersion
	Score        float64
	Severity     string
	VectorString string
}

// Client is the NVD API client with rate limiting and caching.
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	cache       map[string]*CVEResponse
	cacheMu     sync.RWMutex
	rateLimiter *rateLimiter
	concurrency int
}

// rateLimiter manages API rate limiting.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	lastReq  time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{
		interval: interval,
	}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed := time.Since(r.lastReq)
	if elapsed < r.interval {
		waitTime := r.interval - elapsed
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
	r.lastReq = time.Now()
	return nil
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithAPIKey sets the NVD API key for higher rate limits.
func WithAPIKey(apiKey string) ClientOption {
	return func(c *Client) {
		c.apiKey = apiKey
		c.rateLimiter = newRateLimiter(rateLimitWithKey)
		c.concurrency = defaultConcurrency
	}
}

// WithBaseURL sets a custom base URL for the NVD API.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithConcurrency sets the number of concurrent API requests.
func WithConcurrency(n int) ClientOption {
	return func(c *Client) {
		if n > 0 {
			c.concurrency = n
		}
	}
}

// NewClient creates a new NVD API client with the given options.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		cache:       make(map[string]*CVEResponse),
		rateLimiter: newRateLimiter(rateLimitWithoutKey),
		concurrency: concurrencyWithoutKey,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Concurrency returns the configured number of concurrent requests.
func (c *Client) Concurrency() int {
	return c.concurrency
}

// GetCVE fetches CVE information by ID with automatic retries.
func (c *Client) GetCVE(ctx context.Context, cveID string) (*CVE, error) {
	c.cacheMu.RLock()
	if resp, ok := c.cache[cveID]; ok {
		c.cacheMu.RUnlock()
		if len(resp.Vulnerabilities) > 0 {
			return &resp.Vulnerabilities[0].CVE, nil
		}
		return nil, fmt.Errorf("CVE not found in cached response: %s", cveID)
	}
	c.cacheMu.RUnlock()

	var lastErr error
	for attempt := range maxRetries {
		if attempt > 0 {
			backoff := c.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		cve, err := c.doGetCVE(ctx, cveID)
		if err == nil {
			return cve, nil
		}

		lastErr = err
		if errors.Is(err, ErrRateLimited) {
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// calculateBackoff computes exponential backoff with jitter.
func (c *Client) calculateBackoff(attempt int) time.Duration {
	backoff := baseBackoff * time.Duration(1<<uint(attempt))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	// Add jitter (0-25% random addition)
	jitter := time.Duration(rand.Int64N(int64(backoff / 4)))
	return backoff + jitter
}

// doGetCVE performs the actual API request.
func (c *Client) doGetCVE(ctx context.Context, cveID string) (*CVE, error) {
	if err := c.rateLimiter.wait(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s?cveId=%s", c.baseURL, cveID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: status %d for %s", ErrRateLimited, resp.StatusCode, cveID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var cveResp CVEResponse
	if err := json.Unmarshal(body, &cveResp); err != nil {
		return nil, fmt.Errorf("failed to parse CVE response: %w", err)
	}

	c.cacheMu.Lock()
	c.cache[cveID] = &cveResp
	c.cacheMu.Unlock()

	if len(cveResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	return &cveResp.Vulnerabilities[0].CVE, nil
}

// BulkFetchRequest represents a request for bulk CVSS score fetching.
type BulkFetchRequest struct {
	CVEID            string
	PreferredVersion CVSSVersion
}

// BulkFetchResult represents the result of a bulk fetch operation.
type BulkFetchResult struct {
	CVEID string
	Score *CVSSScore
	Error error
}

// BulkGetCVSSScores fetches multiple CVSS scores concurrently.
func (c *Client) BulkGetCVSSScores(ctx context.Context, requests []BulkFetchRequest) []BulkFetchResult {
	results := make([]BulkFetchResult, len(requests))

	type job struct {
		index   int
		request BulkFetchRequest
	}

	jobs := make(chan job, len(requests))
	resultCh := make(chan struct {
		index  int
		result BulkFetchResult
	}, len(requests))

	var wg sync.WaitGroup
	for range c.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				score, err := c.GetCVSSScore(ctx, j.request.CVEID, j.request.PreferredVersion)
				resultCh <- struct {
					index  int
					result BulkFetchResult
				}{
					index: j.index,
					result: BulkFetchResult{
						CVEID: j.request.CVEID,
						Score: score,
						Error: err,
					},
				}
			}
		}()
	}

	go func() {
		for i, req := range requests {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- job{index: i, request: req}:
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for r := range resultCh {
		results[r.index] = r.result
	}

	return results
}

// GetCVSSScore fetches the CVSS score for a CVE ID.
func (c *Client) GetCVSSScore(ctx context.Context, cveID string, preferredVersion CVSSVersion) (*CVSSScore, error) {
	cve, err := c.GetCVE(ctx, cveID)
	if err != nil {
		return nil, err
	}

	return c.extractCVSSScore(cve, preferredVersion)
}

// extractCVSSScore extracts the CVSS score from a CVE based on preferred version.
func (c *Client) extractCVSSScore(cve *CVE, preferredVersion CVSSVersion) (*CVSSScore, error) {
	extractors := c.getExtractorsByPriority(preferredVersion)

	for _, extract := range extractors {
		if score := extract(cve); score != nil {
			return score, nil
		}
	}

	return nil, fmt.Errorf("no CVSS score found for CVE: %s", cve.ID)
}

// getExtractorsByPriority returns score extractors ordered by preference.
func (c *Client) getExtractorsByPriority(preferredVersion CVSSVersion) []func(*CVE) *CVSSScore {
	v4 := c.extractV4Score
	v31 := c.extractV31Score
	v3 := c.extractV3Score
	v2 := c.extractV2Score

	switch preferredVersion {
	case CVSSVersionV4:
		return []func(*CVE) *CVSSScore{v4, v31, v3, v2}
	case CVSSVersionV2:
		return []func(*CVE) *CVSSScore{v2, v31, v3, v4}
	default: // v3, v31
		return []func(*CVE) *CVSSScore{v31, v3, v4, v2}
	}
}

func (c *Client) extractV4Score(cve *CVE) *CVSSScore {
	if len(cve.Metrics.CVSSMetricV40) > 0 {
		m := cve.Metrics.CVSSMetricV40[0]
		return &CVSSScore{
			CVEID:        cve.ID,
			Version:      CVSSVersionV4,
			Score:        m.CVSSData.BaseScore,
			Severity:     m.CVSSData.BaseSeverity,
			VectorString: m.CVSSData.VectorString,
		}
	}
	return nil
}

func (c *Client) extractV31Score(cve *CVE) *CVSSScore {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		m := cve.Metrics.CVSSMetricV31[0]
		return &CVSSScore{
			CVEID:        cve.ID,
			Version:      CVSSVersionV31,
			Score:        m.CVSSData.BaseScore,
			Severity:     m.CVSSData.BaseSeverity,
			VectorString: m.CVSSData.VectorString,
		}
	}
	return nil
}

func (c *Client) extractV3Score(cve *CVE) *CVSSScore {
	if len(cve.Metrics.CVSSMetricV30) > 0 {
		m := cve.Metrics.CVSSMetricV30[0]
		return &CVSSScore{
			CVEID:        cve.ID,
			Version:      CVSSVersionV3,
			Score:        m.CVSSData.BaseScore,
			Severity:     m.CVSSData.BaseSeverity,
			VectorString: m.CVSSData.VectorString,
		}
	}
	return nil
}

func (c *Client) extractV2Score(cve *CVE) *CVSSScore {
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		m := cve.Metrics.CVSSMetricV2[0]
		return &CVSSScore{
			CVEID:        cve.ID,
			Version:      CVSSVersionV2,
			Score:        m.CVSSData.BaseScore,
			Severity:     m.BaseSeverity,
			VectorString: m.CVSSData.VectorString,
		}
	}
	return nil
}

// GetDescription returns the English description of a CVE.
func (cve *CVE) GetDescription() string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}
