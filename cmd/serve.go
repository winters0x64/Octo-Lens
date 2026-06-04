package cmd

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/scanner"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/web"
)

var (
	flagAddr               string
	flagPort               int
	flagPassword           string
	flagTLSCert            string
	flagTLSKey             string
	flagScanInterval       time.Duration
	flagPolicyPath         string
	flagSlackWebhook       string
	flagWebhookSecret      string
	flagDatabaseURL        string
	flagAutoMigrate        bool
	flagEventRetentionDays int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web dashboard with continuous monitoring",
	Long: `Start the PAT Monitor dashboard server with optional scheduled scanning,
policy enforcement, Slack alerts, and GitHub webhook support.

The server provides a web dashboard and API for monitoring PATs, Apps, and
SSO credentials. It can automatically rescan on an interval and alert via
Slack when policy violations are detected.

When DATABASE_URL is set, scan results are persisted to Postgres with an
append-only event log capturing status flips and watched-field changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve from env vars
		if flagPassword == "" {
			flagPassword = os.Getenv("PAT_MONITOR_PASSWORD")
		}
		if flagSlackWebhook == "" {
			flagSlackWebhook = os.Getenv("SLACK_WEBHOOK_URL")
		}
		if flagWebhookSecret == "" {
			flagWebhookSecret = os.Getenv("GITHUB_WEBHOOK_SECRET")
		}
		if flagPolicyPath == "" {
			flagPolicyPath = os.Getenv("PAT_MONITOR_POLICY_PATH")
		}
		if flagDatabaseURL == "" {
			flagDatabaseURL = os.Getenv("DATABASE_URL")
		}

		var st *store.Store
		if flagDatabaseURL != "" {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			s, err := store.New(ctx, flagDatabaseURL)
			cancel()
			if err != nil {
				return err
			}
			st = s
			defer st.Close()

			if flagAutoMigrate {
				ctx2, cancel2 := context.WithTimeout(cmd.Context(), 60*time.Second)
				if err := st.RunMigrations(ctx2); err != nil {
					cancel2()
					return err
				}
				cancel2()
				log.Printf("Migrations applied")
			}
			log.Printf("Persistence enabled (Postgres)")
		} else {
			log.Printf("Persistence disabled (DATABASE_URL not set)")
		}

		_ = flagEventRetentionDays // wired for future pruning job; default 0 = keep forever

		sc := scanner.New(ghService)
		srv := web.NewServer(ghService, sc, st, flagOrg, flagPassword)

		return srv.ListenAndServe(web.Config{
			Addr:          flagAddr,
			Port:          flagPort,
			Password:      flagPassword,
			TLSCert:       flagTLSCert,
			TLSKey:        flagTLSKey,
			Org:           flagOrg,
			ScanInterval:  flagScanInterval,
			PolicyPath:    flagPolicyPath,
			SlackWebhook:  flagSlackWebhook,
			WebhookSecret: flagWebhookSecret,
		})
	},
}

func init() {
	serveCmd.Flags().StringVar(&flagAddr, "addr", "127.0.0.1", "Bind address (default: 127.0.0.1, local-only)")
	serveCmd.Flags().IntVar(&flagPort, "port", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&flagPassword, "password", "", "Password for dashboard login (username: admin, env: PAT_MONITOR_PASSWORD)")
	serveCmd.Flags().StringVar(&flagTLSCert, "tls-cert", "", "Path to TLS certificate file")
	serveCmd.Flags().StringVar(&flagTLSKey, "tls-key", "", "Path to TLS private key file")
	serveCmd.Flags().DurationVar(&flagScanInterval, "scan-interval", 1*time.Hour, "Auto-rescan interval (e.g. 5m, 1h, 0 to disable)")
	serveCmd.Flags().StringVar(&flagPolicyPath, "policy", "", "Path to policy YAML file (env: PAT_MONITOR_POLICY_PATH)")
	serveCmd.Flags().StringVar(&flagSlackWebhook, "slack-webhook", "", "Slack webhook URL for alerts (env: SLACK_WEBHOOK_URL)")
	serveCmd.Flags().StringVar(&flagWebhookSecret, "webhook-secret", "", "GitHub webhook secret for signature verification (env: GITHUB_WEBHOOK_SECRET)")
	serveCmd.Flags().StringVar(&flagDatabaseURL, "database-url", "", "Postgres connection string (env: DATABASE_URL). When unset, persistence is disabled.")
	serveCmd.Flags().BoolVar(&flagAutoMigrate, "auto-migrate", true, "Apply embedded goose migrations on startup")
	serveCmd.Flags().IntVar(&flagEventRetentionDays, "event-retention-days", 0, "Prune events older than N days (0 = keep forever)")
	rootCmd.AddCommand(serveCmd)
}
