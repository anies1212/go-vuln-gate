# go-vuln-gate Example

This directory contains a sample Go application with intentionally vulnerable dependencies for testing `go-vuln-gate`.

## Vulnerable Dependencies

| Package | Version | Known Vulnerabilities |
|---------|---------|----------------------|
| golang.org/x/net | v0.0.0-20211112202133-69e39bad7dc2 | HTTP/2 DoS, CONTINUATION flood |

## Testing go-vuln-gate

### 1. Build go-vuln-gate (from repository root)

```bash
go build -o go-vuln-gate ./cmd/go-vuln-gate
```

### 2. Install dependencies for the example

```bash
cd example
go mod tidy
```

### 3. Run go-vuln-gate

```bash
# Default: only check vulnerabilities that are called by your code
../go-vuln-gate ./...

# Include all vulnerabilities (even those not called)
../go-vuln-gate --include-all ./...

# Lower threshold to see more vulnerabilities
../go-vuln-gate --threshold 4.0 ./...

# Only recent vulnerabilities (last 2 years)
../go-vuln-gate --max-age 2 ./...

# JSON output
../go-vuln-gate --output json ./...

# SARIF output (for GitHub Code Scanning)
../go-vuln-gate --output sarif ./...

# With NVD API key for faster scanning (recommended)
../go-vuln-gate --nvd-api-key YOUR_API_KEY ./...
```

### 4. Expected output

```
Running govulncheck on ./......
Found 15 called vulnerabilities (out of 142 total), fetching CVSS scores...
No NVD API key provided (rate limited to 1 request per 6 seconds)

=== go-vuln-gate Report ===

Threshold: 7.0 (CVSS v31)
Total vulnerabilities found: 10
Vulnerabilities above threshold: 5
Highest CVSS score: 7.5 (HIGH)

--- Vulnerabilities Above Threshold ---

  GO-2024-2687
    CVE: CVE-2023-45288
    CVSS: 7.5 (HIGH, v31)
    Summary: HTTP/2 CONTINUATION flood in net/http
    Affected: stdlib, golang.org/x/net
    Fixed in: v0.23.0

  ...

[FAIL] Found 5 vulnerabilities above threshold 7.0
```

## Updating Dependencies

To fix vulnerabilities, update the dependencies in `go.mod`:

```bash
go get -u golang.org/x/net
go mod tidy
```

Then re-run `go-vuln-gate` to verify the fixes.

## Notes

- By default, `go-vuln-gate` only checks vulnerabilities that are actually called by your code (symbol-level analysis)
- Use `--include-all` to check all vulnerabilities in your dependencies
- Without an NVD API key, requests are rate-limited to 1 per 6 seconds
- Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key
