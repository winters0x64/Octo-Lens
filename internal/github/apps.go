package github

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v68/github"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ListInstalledApps returns all GitHub Apps installed in the organization.
func (s *GitHubService) ListInstalledApps(ctx context.Context) ([]models.AppInstallation, error) {
	apps, err := Paginate(ctx, func(opts gh.ListOptions) ([]*gh.Installation, *gh.Response, error) {
		result, resp, err := s.client.Organizations.ListInstallations(ctx, s.org, &opts)
		if err != nil {
			return nil, resp, err
		}
		return result.Installations, resp, nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing installed apps: %w", err)
	}

	var result []models.AppInstallation
	for _, inst := range apps {
		app := mapInstallation(inst)
		result = append(result, app)
	}

	return result, nil
}

func mapInstallation(inst *gh.Installation) models.AppInstallation {
	app := models.AppInstallation{
		ID:                  inst.GetID(),
		AppSlug:             inst.GetAppSlug(),
		AppName:             inst.GetAppSlug(),
		RepositorySelection: inst.GetRepositorySelection(),
		CreatedAt:           inst.GetCreatedAt().Time,
		UpdatedAt:           inst.GetUpdatedAt().Time,
		Suspended:           inst.SuspendedAt != nil,
		Events:              inst.Events,
	}

	if inst.Permissions != nil {
		app.Permissions = extractInstallationPermissions(inst.Permissions)

		for _, p := range app.Permissions {
			switch p.Risk {
			case models.RiskHigh:
				app.HighRiskCount++
			case models.RiskMedium:
				app.MediumRiskCount++
			case models.RiskLow:
				app.LowRiskCount++
			}
		}
	}

	return app
}

func extractInstallationPermissions(perms *gh.InstallationPermissions) []models.Permission {
	permMap := map[string]string{}

	addIfSet := func(name string, val *string) {
		if val != nil && *val != "" {
			permMap[name] = *val
		}
	}

	addIfSet("actions", perms.Actions)
	addIfSet("administration", perms.Administration)
	addIfSet("checks", perms.Checks)
	addIfSet("contents", perms.Contents)
	addIfSet("deployments", perms.Deployments)
	addIfSet("environments", perms.Environments)
	addIfSet("issues", perms.Issues)
	addIfSet("members", perms.Members)
	addIfSet("metadata", perms.Metadata)
	addIfSet("organization_administration", perms.OrganizationAdministration)
	addIfSet("organization_hooks", perms.OrganizationHooks)
	addIfSet("organization_plan", perms.OrganizationPlan)
	addIfSet("organization_projects", perms.OrganizationProjects)
	addIfSet("organization_secrets", perms.OrganizationSecrets)
	addIfSet("organization_user_blocking", perms.OrganizationUserBlocking)
	addIfSet("packages", perms.Packages)
	addIfSet("pages", perms.Pages)
	addIfSet("pull_requests", perms.PullRequests)
	addIfSet("repository_hooks", perms.RepositoryHooks)
	addIfSet("repository_projects", perms.RepositoryProjects)
	addIfSet("secrets", perms.Secrets)
	addIfSet("security_events", perms.SecurityEvents)
	addIfSet("single_file", perms.SingleFile)
	addIfSet("statuses", perms.Statuses)
	addIfSet("vulnerability_alerts", perms.VulnerabilityAlerts)
	addIfSet("workflows", perms.Workflows)

	return mapToPermissions(permMap)
}
