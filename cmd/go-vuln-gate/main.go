package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/anies1212/go-vuln-gate/internal/filter"
	"github.com/anies1212/go-vuln-gate/internal/govulncheck"
	"github.com/anies1212/go-vuln-gate/internal/nvd"
	"github.com/anies1212/go-vuln-gate/internal/output"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type config struct {
	threshold    float64
	cvssVersion  string
	nvdAPIKey    string
	outputFormat string
	failOnNoCVSS bool
	maxAgeYears  int
	concurrency  int
	includeAll   bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := &config{}

	rootCmd := &cobra.Command{
		Use:   "go-vuln-gate [flags] [package]",
		Short: "Filter govulncheck results by CVSS score",
		Long: `go-vuln-gate runs govulncheck and filters vulnerabilities by CVSS score.

It fetches CVSS scores from NVD API and fails if any vulnerability
exceeds the specified threshold.

Examples:
  # Scan current directory with default threshold (7.0)
  go-vuln-gate ./...

  # Scan with custom threshold
  go-vuln-gate --threshold 9.0 ./...

  # Only check vulnerabilities from the last 3 years
  go-vuln-gate --max-age 3 ./...

  # Use NVD API key for faster requests
  go-vuln-gate --nvd-api-key $NVD_API_KEY ./...

  # Output as JSON
  go-vuln-gate --output json ./...`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "./..."
			if len(args) > 0 {
				target = args[0]
			}
			return runScan(cmd.Context(), cfg, target)
		},
		SilenceUsage: true,
	}

	rootCmd.Flags().Float64VarP(&cfg.threshold, "threshold", "t", 7.0, "CVSS score threshold (vulnerabilities at or above this score will cause failure)")
	rootCmd.Flags().StringVarP(&cfg.cvssVersion, "cvss-version", "c", "v3", "CVSS version to use (v2, v3, v4)")
	rootCmd.Flags().StringVarP(&cfg.nvdAPIKey, "nvd-api-key", "k", "", "NVD API key (can also use NVD_API_KEY env var)")
	rootCmd.Flags().StringVarP(&cfg.outputFormat, "output", "o", "text", "Output format (text, json, sarif)")
	rootCmd.Flags().BoolVar(&cfg.failOnNoCVSS, "fail-on-no-cvss", false, "Fail if vulnerabilities without CVSS score are found")
	rootCmd.Flags().IntVar(&cfg.maxAgeYears, "max-age", 0, "Only check vulnerabilities published within the last N years (0 = no limit)")
	rootCmd.Flags().IntVar(&cfg.concurrency, "concurrency", 0, "Number of concurrent NVD API requests (default: 5 with API key, 1 without)")
	rootCmd.Flags().BoolVar(&cfg.includeAll, "include-all", false, "Include all vulnerabilities, not just those called by your code")

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	return rootCmd.ExecuteContext(ctx)
}

func runScan(ctx context.Context, cfg *config, target string) error {
	// Get NVD API key from environment if not provided via flag
	nvdAPIKey := cfg.nvdAPIKey
	if nvdAPIKey == "" {
		nvdAPIKey = os.Getenv("NVD_API_KEY")
	}

	// Parse CVSS version
	cvssVersion, err := parseCVSSVersion(cfg.cvssVersion)
	if err != nil {
		return err
	}

	// Parse output format
	outputFormat, err := output.ParseFormat(cfg.outputFormat)
	if err != nil {
		return err
	}

	// Run govulncheck
	fmt.Fprintf(os.Stderr, "Running govulncheck on %s...\n", target)
	runner := govulncheck.NewRunner()
	result, err := runner.Run(ctx, target)
	if err != nil {
		return fmt.Errorf("govulncheck failed: %w", err)
	}

	if len(result.Findings) == 0 && !cfg.includeAll {
		fmt.Fprintf(os.Stderr, "No called vulnerabilities found by govulncheck.\n")
		if len(result.OSVs) > 0 {
			fmt.Fprintf(os.Stderr, "(Found %d vulnerabilities in dependencies, use --include-all to check them)\n", len(result.OSVs))
		}
		formatter := output.NewFormatter(outputFormat, os.Stdout)
		return formatter.Format(&filter.FilterResult{
			Threshold:   cfg.threshold,
			CVSSVersion: cvssVersion,
		})
	}

	if cfg.includeAll {
		fmt.Fprintf(os.Stderr, "Found %d total vulnerabilities, fetching CVSS scores...\n", len(result.OSVs))
	} else {
		fmt.Fprintf(os.Stderr, "Found %d called vulnerabilities (out of %d total), fetching CVSS scores...\n", len(result.Findings), len(result.OSVs))
	}

	// Create NVD client
	nvdOpts := []nvd.ClientOption{}
	if nvdAPIKey != "" {
		nvdOpts = append(nvdOpts, nvd.WithAPIKey(nvdAPIKey))
		fmt.Fprintf(os.Stderr, "Using NVD API key (parallel requests enabled)\n")
	} else {
		fmt.Fprintf(os.Stderr, "No NVD API key provided (rate limited to 1 request per 6 seconds)\n")
	}
	if cfg.concurrency > 0 {
		nvdOpts = append(nvdOpts, nvd.WithConcurrency(cfg.concurrency))
	}
	nvdClient := nvd.NewClient(nvdOpts...)

	// Apply CVSS filtering
	filterOpts := []filter.FilterOption{
		filter.WithThreshold(cfg.threshold),
		filter.WithCVSSVersion(cvssVersion),
		filter.WithFailOnNoCVSS(cfg.failOnNoCVSS),
		filter.WithCalledOnly(!cfg.includeAll),
	}
	if cfg.maxAgeYears > 0 {
		filterOpts = append(filterOpts, filter.WithMaxAgeYears(cfg.maxAgeYears))
		fmt.Fprintf(os.Stderr, "Filtering vulnerabilities published within the last %d years\n", cfg.maxAgeYears)
	}

	f := filter.NewFilter(nvdClient, filterOpts...)

	filterResult, err := f.Apply(ctx, result)
	if err != nil {
		return fmt.Errorf("filtering failed: %w", err)
	}

	// Output results
	formatter := output.NewFormatter(outputFormat, os.Stdout)
	if err := formatter.Format(filterResult); err != nil {
		return fmt.Errorf("output formatting failed: %w", err)
	}

	// Exit with error if vulnerabilities exceed threshold
	if filterResult.ShouldFail {
		os.Exit(1)
	}

	return nil
}

func parseCVSSVersion(s string) (nvd.CVSSVersion, error) {
	switch s {
	case "v2":
		return nvd.CVSSVersionV2, nil
	case "v3", "v31", "v3.1":
		return nvd.CVSSVersionV31, nil
	case "v4", "v40", "v4.0":
		return nvd.CVSSVersionV4, nil
	default:
		return "", fmt.Errorf("unknown CVSS version: %s (supported: v2, v3, v4)", s)
	}
}
