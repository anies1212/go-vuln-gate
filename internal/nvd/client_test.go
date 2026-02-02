package nvd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetCVE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/", r.URL.Path)
		assert.Equal(t, "CVE-2024-0001", r.URL.Query().Get("cveId"))

		resp := CVEResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []Vulnerability{
				{
					CVE: CVE{
						ID:           "CVE-2024-0001",
						VulnStatus:   "Analyzed",
						Descriptions: []Description{{Lang: "en", Value: "Test vulnerability"}},
						Metrics: Metrics{
							CVSSMetricV31: []CVSSMetricV31{
								{
									Source: "nvd@nist.gov",
									Type:   "Primary",
									CVSSData: CVSSDataV3{
										Version:      "3.1",
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										BaseScore:    9.8,
										BaseSeverity: "CRITICAL",
									},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	cve, err := client.GetCVE(context.Background(), "CVE-2024-0001")

	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-0001", cve.ID)
	assert.Equal(t, "Test vulnerability", cve.GetDescription())
}

func TestClient_GetCVSSScore_V31(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CVEResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []Vulnerability{
				{
					CVE: CVE{
						ID: "CVE-2024-0001",
						Metrics: Metrics{
							CVSSMetricV31: []CVSSMetricV31{
								{
									CVSSData: CVSSDataV3{
										Version:      "3.1",
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										BaseScore:    9.8,
										BaseSeverity: "CRITICAL",
									},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	score, err := client.GetCVSSScore(context.Background(), "CVE-2024-0001", CVSSVersionV31)

	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-0001", score.CVEID)
	assert.Equal(t, CVSSVersionV31, score.Version)
	assert.Equal(t, 9.8, score.Score)
	assert.Equal(t, "CRITICAL", score.Severity)
}

func TestClient_GetCVSSScore_V4(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CVEResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []Vulnerability{
				{
					CVE: CVE{
						ID: "CVE-2024-0001",
						Metrics: Metrics{
							CVSSMetricV40: []CVSSMetricV4{
								{
									CVSSData: CVSSDataV4{
										Version:      "4.0",
										VectorString: "CVSS:4.0/...",
										BaseScore:    8.5,
										BaseSeverity: "HIGH",
									},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	score, err := client.GetCVSSScore(context.Background(), "CVE-2024-0001", CVSSVersionV4)

	require.NoError(t, err)
	assert.Equal(t, CVSSVersionV4, score.Version)
	assert.Equal(t, 8.5, score.Score)
}

func TestClient_GetCVSSScore_Fallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CVEResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []Vulnerability{
				{
					CVE: CVE{
						ID: "CVE-2024-0001",
						Metrics: Metrics{
							CVSSMetricV2: []CVSSMetricV2{
								{
									CVSSData: CVSSDataV2{
										Version:   "2.0",
										BaseScore: 7.5,
									},
									BaseSeverity: "HIGH",
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	// Request v3, but fallback to v2 when v3 is not available
	score, err := client.GetCVSSScore(context.Background(), "CVE-2024-0001", CVSSVersionV31)

	require.NoError(t, err)
	assert.Equal(t, CVSSVersionV2, score.Version)
	assert.Equal(t, 7.5, score.Score)
}

func TestClient_GetCVE_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	_, err := client.GetCVE(context.Background(), "CVE-2024-9999")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestClient_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := CVEResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []Vulnerability{
				{CVE: CVE{ID: "CVE-2024-0001"}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	// First request
	_, err := client.GetCVE(context.Background(), "CVE-2024-0001")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second request (from cache)
	_, err = client.GetCVE(context.Background(), "CVE-2024-0001")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount) // API should not be called again
}

func TestCVE_GetDescription(t *testing.T) {
	tests := []struct {
		name         string
		descriptions []Description
		expected     string
	}{
		{
			name: "english available",
			descriptions: []Description{
				{Lang: "es", Value: "Spanish"},
				{Lang: "en", Value: "English"},
			},
			expected: "English",
		},
		{
			name: "no english",
			descriptions: []Description{
				{Lang: "es", Value: "Spanish"},
			},
			expected: "Spanish",
		},
		{
			name:         "empty",
			descriptions: []Description{},
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cve := &CVE{Descriptions: tt.descriptions}
			assert.Equal(t, tt.expected, cve.GetDescription())
		})
	}
}
