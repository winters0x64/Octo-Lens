package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v68/github"
)

// requestTimeout bounds a single GitHub API round-trip. http.DefaultTransport's
// TLSHandshakeTimeout only covers the handshake phase — a connection that gets
// wedged afterward (a TLS-intercepting proxy silently dropping the response,
// e.g.) would otherwise hang forever with no way to recover short of killing
// the process. This is generous for a real GitHub API call, which normally
// completes in well under a second.
const requestTimeout = 60 * time.Second

// NewAppLevelClient creates a GitHub client authenticated as the App itself (JWT),
// rather than as an installation. Required for operations like suspend/unsuspend.
func NewAppLevelClient(appID int64, privateKey []byte) (*github.Client, error) {
	atr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating app transport: %w", err)
	}
	return github.NewClient(&http.Client{Transport: atr, Timeout: requestTimeout}), nil
}

// NewGitHubClient creates an authenticated GitHub client using GitHub App credentials.
// If installationID is 0, it auto-discovers the installation for the given org.
func NewGitHubClient(ctx context.Context, appID, installationID int64, privateKey []byte, org string) (*github.Client, error) {
	if installationID == 0 {
		discovered, err := discoverInstallationID(ctx, appID, privateKey, org)
		if err != nil {
			return nil, fmt.Errorf("auto-discovering installation ID: %w", err)
		}
		installationID = discovered
	}

	itr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating installation transport: %w", err)
	}

	client := github.NewClient(&http.Client{Transport: itr, Timeout: requestTimeout})
	return client, nil
}

func discoverInstallationID(ctx context.Context, appID int64, privateKey []byte, org string) (int64, error) {
	atr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, privateKey)
	if err != nil {
		return 0, fmt.Errorf("creating app transport: %w", err)
	}

	client := github.NewClient(&http.Client{Transport: atr, Timeout: requestTimeout})

	installation, _, err := client.Apps.FindOrganizationInstallation(ctx, org)
	if err != nil {
		return 0, fmt.Errorf("finding installation for org %q: %w", org, err)
	}

	return installation.GetID(), nil
}
