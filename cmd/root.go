package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-github/v68/github"
	"github.com/spf13/cobra"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/auth"
	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
)

var (
	flagOrg            string
	flagAppID          int64
	flagPrivateKey     string
	flagInstallationID int64

	ghClient  *github.Client
	ghService *ghservice.GitHubService
)

var rootCmd = &cobra.Command{
	Use:   "github-pat-monitor",
	Short: "Centralized visibility into GitHub PATs and Apps for your organization",
	Long: `github-pat-monitor provides a CLI and web dashboard to monitor
fine-grained Personal Access Tokens and installed GitHub Apps
across your GitHub organization.

Requires a GitHub App with "Personal access tokens: Read" and
"Administration: Read" organization permissions.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip auth for help commands
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}
		return initClient(cmd.Context())
	},
}

func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagOrg, "org", "", "GitHub organization name (env: GITHUB_ORG)")
	rootCmd.PersistentFlags().Int64Var(&flagAppID, "app-id", 0, "GitHub App ID (env: GITHUB_APP_ID)")
	rootCmd.PersistentFlags().StringVar(&flagPrivateKey, "private-key", "", "Path to GitHub App private key .pem file (env: GITHUB_APP_PRIVATE_KEY_PATH)")
	rootCmd.PersistentFlags().Int64Var(&flagInstallationID, "installation-id", 0, "GitHub App installation ID (auto-discovered if omitted) (env: GITHUB_INSTALLATION_ID)")
}

func initClient(ctx context.Context) error {
	// Resolve org from flag or env
	if flagOrg == "" {
		flagOrg = os.Getenv("GITHUB_ORG")
	}
	if flagOrg == "" {
		return fmt.Errorf("--org or GITHUB_ORG is required")
	}

	// Resolve app ID from flag or env
	if flagAppID == 0 {
		if v := os.Getenv("GITHUB_APP_ID"); v != "" {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
			}
			flagAppID = id
		}
	}
	if flagAppID == 0 {
		return fmt.Errorf("--app-id or GITHUB_APP_ID is required")
	}

	// Resolve installation ID from flag or env
	if flagInstallationID == 0 {
		if v := os.Getenv("GITHUB_INSTALLATION_ID"); v != "" {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
			}
			flagInstallationID = id
		}
	}

	// Load private key
	key, err := auth.LoadPrivateKey(flagPrivateKey)
	if err != nil {
		return err
	}

	// Create authenticated client
	ghClient, err = auth.NewGitHubClient(ctx, flagAppID, flagInstallationID, key, flagOrg)
	if err != nil {
		return err
	}

	ghService = ghservice.NewGitHubService(ghClient, flagOrg)
	return nil
}
