package render

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

func RenderCSV(w io.Writer, report *models.OrgReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// PATs section
	if err := cw.Write([]string{"# Personal Access Tokens"}); err != nil {
		return err
	}
	if err := cw.Write([]string{"ID", "Owner", "Token Name", "Repo Access", "Permissions", "Granted", "Expires", "Last Used", "Expired"}); err != nil {
		return err
	}
	for _, p := range report.PATs {
		expires := ""
		if p.TokenExpiresAt != nil {
			expires = p.TokenExpiresAt.Format("2006-01-02")
		}
		lastUsed := ""
		if p.TokenLastUsedAt != nil {
			lastUsed = p.TokenLastUsedAt.Format("2006-01-02")
		}
		if err := cw.Write([]string{
			fmt.Sprintf("%d", p.ID),
			p.OwnerLogin,
			p.TokenName,
			p.RepositorySelection,
			formatPermissionsCSV(p.Permissions),
			p.AccessGrantedAt.Format("2006-01-02"),
			expires,
			lastUsed,
			fmt.Sprintf("%t", p.TokenExpired),
		}); err != nil {
			return err
		}
	}

	// Blank line separator
	if err := cw.Write([]string{}); err != nil {
		return err
	}

	// Apps section
	if err := cw.Write([]string{"# Installed GitHub Apps"}); err != nil {
		return err
	}
	if err := cw.Write([]string{"ID", "App Name", "App Slug", "Repo Access", "Permissions", "Events", "Installed", "Suspended"}); err != nil {
		return err
	}
	for _, a := range report.Apps {
		if err := cw.Write([]string{
			fmt.Sprintf("%d", a.ID),
			a.AppName,
			a.AppSlug,
			a.RepositorySelection,
			formatPermissionsCSV(a.Permissions),
			strings.Join(a.Events, ";"),
			a.CreatedAt.Format("2006-01-02"),
			fmt.Sprintf("%t", a.Suspended),
		}); err != nil {
			return err
		}
	}

	// SSO Credentials section
	if len(report.SSOCredentials) > 0 {
		if err := cw.Write([]string{}); err != nil {
			return err
		}
		if err := cw.Write([]string{"# SSO Authorized Credentials"}); err != nil {
			return err
		}
		if err := cw.Write([]string{"ID", "Owner", "Type", "Title", "Token Last 8", "Scopes", "Authorized", "Last Accessed", "Expires"}); err != nil {
			return err
		}
		for _, c := range report.SSOCredentials {
			lastAccessed := ""
			if c.CredentialAccessedAt != nil {
				lastAccessed = c.CredentialAccessedAt.Format("2006-01-02")
			}
			expires := ""
			if c.AuthorizedCredentialExpAt != nil {
				expires = c.AuthorizedCredentialExpAt.Format("2006-01-02")
			}
			if err := cw.Write([]string{
				fmt.Sprintf("%d", c.CredentialID),
				c.Login,
				c.CredentialType,
				c.AuthorizedCredentialTitle,
				c.TokenLastEight,
				strings.Join(c.Scopes, ";"),
				c.CredentialAuthorizedAt.Format("2006-01-02"),
				lastAccessed,
				expires,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func formatPermissionsCSV(perms []models.Permission) string {
	var parts []string
	for _, p := range perms {
		parts = append(parts, fmt.Sprintf("%s:%s", p.Name, p.Level))
	}
	return strings.Join(parts, ";")
}
