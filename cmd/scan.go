package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/render"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/scanner"
)

var (
	flagOutput     string
	flagScanPolicy string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the organization for PATs and installed GitHub Apps",
	Long: `Scan the organization and output results in the specified format.

When --policy is set, the scan results are evaluated against the policy rules.
If violations are found, the exit code is 1 (useful as a CI gate).

Exit codes:
  0  No policy violations (or no policy specified)
  1  Policy violations found
  2  Scan error`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := scanner.New(ghService)

		fmt.Fprintf(os.Stderr, "Scanning organization %q...\n", flagOrg)

		result, err := s.Scan(cmd.Context())
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(2)
		}
		report := result.Report
		report.Org = flagOrg
		if summary := result.PhaseErrorSummary(); summary != "" {
			fmt.Fprintf(os.Stderr, "WARNING: partial scan — %s\n", summary)
		}

		switch flagOutput {
		case "json":
			if err := render.RenderJSON(os.Stdout, report); err != nil {
				return err
			}
		case "csv":
			if err := render.RenderCSV(os.Stdout, report); err != nil {
				return err
			}
		case "table":
			render.RenderTable(os.Stdout, report)
		default:
			return fmt.Errorf("unknown output format %q (use: table, json, csv)", flagOutput)
		}

		// Policy evaluation
		if flagScanPolicy == "" {
			flagScanPolicy = os.Getenv("PAT_MONITOR_POLICY_PATH")
		}
		if flagScanPolicy != "" {
			pol, err := policy.LoadFromFile(flagScanPolicy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load policy: %v\n", err)
				os.Exit(2)
			}

			violations := pol.Evaluate(report)
			if len(violations) > 0 {
				fmt.Fprintf(os.Stderr, "\n--- Policy Violations (%d) ---\n", len(violations))
				for _, v := range violations {
					severity := "LOW"
					if v.Severity == "high" {
						severity = "HIGH"
					} else if v.Severity == "medium" {
						severity = "MED "
					}
					fmt.Fprintf(os.Stderr, "  [%s] %s — %s (%s)\n", severity, v.Resource, v.Message, v.Rule)
				}
				fmt.Fprintf(os.Stderr, "\nExit code: 1 (violations found)\n")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\nPolicy check passed: no violations\n")
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "table", "Output format: table, json, csv")
	scanCmd.Flags().StringVar(&flagScanPolicy, "policy", "", "Path to policy YAML file for CI gating (env: PAT_MONITOR_POLICY_PATH)")
	rootCmd.AddCommand(scanCmd)
}
