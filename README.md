# go-vuln-gate

[![Go Reference](https://pkg.go.dev/badge/github.com/anies1212/go-vuln-gate.svg)](https://pkg.go.dev/github.com/anies1212/go-vuln-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A CI/CD gate that filters govulncheck results by CVSS score threshold. Only fail your pipeline when high-severity vulnerabilities are detected.

## Features

- **CVSS Score Filtering**: Only detect vulnerabilities above a threshold (default: 7.0)
- **Called Vulnerabilities Only**: By default, only checks vulnerabilities actually called by your code
- **Age Filter**: Filter vulnerabilities published within the last N years
- **Multiple CVSS Versions**: Supports CVSS v2, v3, and v4
- **NVD API Integration**: Automatically fetches CVSS scores from NVD API
- **Parallel Processing**: Concurrent CVSS score fetching with API key
- **Auto Retry**: Exponential backoff retry on rate limits
- **Multiple Output Formats**: text, JSON, and SARIF formats
- **GitHub Action**: Easy integration into CI/CD pipelines

## Installation

### CLI

```bash
go install github.com/anies1212/go-vuln-gate/cmd/go-vuln-gate@latest
```

### Prerequisites

- Go 1.21 or later
- `govulncheck` installed

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## CLI Usage

### Basic

```bash
# Scan current directory (threshold: 7.0)
go-vuln-gate ./...

# Custom threshold
go-vuln-gate --threshold 9.0 ./...

# Only check vulnerabilities from the last 3 years
go-vuln-gate --max-age 3 ./...

# Include all vulnerabilities (not just called ones)
go-vuln-gate --include-all ./...

# Use NVD API key (faster with parallel requests)
go-vuln-gate --nvd-api-key $NVD_API_KEY ./...

# JSON output
go-vuln-gate --output json ./...

# SARIF output (for GitHub Code Scanning)
go-vuln-gate --output sarif ./...
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--threshold` | `-t` | `7.0` | CVSS score threshold |
| `--cvss-version` | `-c` | `v3` | CVSS version (v2, v3, v4) |
| `--nvd-api-key` | `-k` | - | NVD API key |
| `--output` | `-o` | `text` | Output format (text, json, sarif) |
| `--fail-on-no-cvss` | - | `false` | Fail if vulnerabilities without CVSS score are found |
| `--max-age` | - | `0` | Only check vulnerabilities from the last N years (0 = no limit) |
| `--include-all` | - | `false` | Include all vulnerabilities, not just called ones |
| `--concurrency` | - | auto | NVD API concurrency (with key: 5, without: 1) |

### Environment Variables

- `NVD_API_KEY`: NVD API key (alternative to `--nvd-api-key`)

## GitHub Action Usage

### Basic

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vuln-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run go-vuln-gate
        uses: anies1212/go-vuln-gate@v1
        with:
          cvss-threshold: '7.0'
          max-age: '3'  # Only last 3 years
          nvd-api-key: ${{ secrets.NVD_API_KEY }}
```

### SARIF Output with Code Scanning

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vuln-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run go-vuln-gate
        uses: anies1212/go-vuln-gate@v1
        with:
          cvss-threshold: '7.0'
          output-format: 'sarif'
          nvd-api-key: ${{ secrets.NVD_API_KEY }}
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Input Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `cvss-threshold` | No | `7.0` | CVSS score threshold |
| `cvss-version` | No | `v3` | CVSS version |
| `go-package` | No | `./...` | Package to scan |
| `nvd-api-key` | No | - | NVD API key |
| `fail-on-no-cvss` | No | `false` | Fail on missing CVSS |
| `output-format` | No | `text` | Output format |
| `max-age` | No | `0` | Only last N years (0 = no limit) |
| `include-all` | No | `false` | Include all vulnerabilities |
| `go-version` | No | `1.21` | Go version |

### Outputs

| Name | Description |
|------|-------------|
| `vulnerabilities-found` | Whether vulnerabilities above threshold were found |
| `vulnerability-count` | Number of vulnerabilities above threshold |
| `highest-cvss` | Highest CVSS score found |
| `report` | Detailed report (JSON) |

## CVSS Score Threshold Guide

| Score | Severity | Recommended Action |
|-------|----------|-------------------|
| 9.0-10.0 | Critical | Immediate action required |
| 7.0-8.9 | High | Prioritize remediation |
| 4.0-6.9 | Medium | Plan remediation |
| 0.1-3.9 | Low | Evaluate risk |

## NVD API

### Rate Limits

The NVD API has rate limits:

- **Without API key**: 1 request per 6 seconds (concurrency: 1)
- **With API key**: 1 request per 0.6 seconds (concurrency: 5)

For scanning many vulnerabilities, we recommend obtaining an API key.

[Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)

### Auto Retry

When rate limited (429 error), the tool automatically retries with exponential backoff:

- 1st retry: after 10 seconds
- 2nd retry: after 20 seconds
- 3rd retry: after 40 seconds (max 60 seconds)

## Output Examples

### Text Format

```
Running govulncheck on ./......
Found 2 called vulnerabilities (out of 10 total), fetching CVSS scores...

=== go-vuln-gate Report ===

Threshold: 7.0 (CVSS v31)
Total vulnerabilities found: 2
Vulnerabilities above threshold: 1
Highest CVSS score: 9.8 (CRITICAL)

--- Vulnerabilities Above Threshold ---

  GO-2024-1234
    CVE: CVE-2024-1234
    CVSS: 9.8 (CRITICAL, v31)
    Summary: Remote code execution vulnerability
    Affected: example.com/vulnerable-lib
    Fixed in: v1.2.3

[FAIL] Found 1 vulnerabilities above threshold 7.0
```

### JSON Format

```json
{
  "summary": {
    "threshold": 7.0,
    "cvss_version": "v31",
    "total_vulnerabilities": 2,
    "filtered_vulnerabilities": 1,
    "highest_score": 9.8,
    "should_fail": true
  },
  "vulnerabilities": [
    {
      "osv_id": "GO-2024-1234",
      "cve_ids": ["CVE-2024-1234"],
      "summary": "Remote code execution vulnerability",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "affected_modules": ["example.com/vulnerable-lib"],
      "fixed_version": "v1.2.3"
    }
  ]
}
```

## How It Works

1. Runs `govulncheck` with JSON output
2. By default, filters to only vulnerabilities that are actually called by your code
3. Fetches CVSS scores from NVD API for each CVE
4. Filters vulnerabilities by CVSS threshold
5. Outputs results and exits with code 1 if vulnerabilities exceed threshold

## License

MIT License
