package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

func RenderTable(w io.Writer, report *models.OrgReport) {
	renderSummary(w, report)
	fmt.Fprintln(w)
	renderPATsTable(w, report.PATs)
	fmt.Fprintln(w)
	renderAppsTable(w, report.Apps)

	if len(report.PendingRequests) > 0 {
		fmt.Fprintln(w)
		renderPendingTable(w, report.PendingRequests)
	}

	if len(report.SSOCredentials) > 0 {
		fmt.Fprintln(w)
		renderSSOTable(w, report.SSOCredentials)
	}
}

func renderSummary(w io.Writer, report *models.OrgReport) {
	s := report.Summary
	fmt.Fprintf(w, "=== Organization: %s (scanned %s) ===\n", report.Org, report.ScannedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "PATs: %d total (%d active, %d expired, %d expiring soon)\n",
		s.TotalPATs, s.ActivePATs, s.ExpiredPATs, s.ExpiringSoon)
	fmt.Fprintf(w, "Apps: %d total (%d with high-risk permissions)\n",
		s.TotalApps, s.HighRiskApps)
	fmt.Fprintf(w, "Pending Requests: %d\n", s.PendingRequests)
	fmt.Fprintf(w, "All-repo access: %d PATs, %d Apps\n", s.AllRepoAccessPATs, s.AllRepoAccessApps)
	if s.SSOCredentials > 0 {
		fmt.Fprintf(w, "SSO Credentials: %d total (%d classic PATs, %d SSH keys)\n",
			s.SSOCredentials, s.SSOClassicPATs, s.SSOSSHKeys)
	}
}

func renderPATsTable(w io.Writer, pats []models.PATInfo) {
	fmt.Fprintln(w, "--- Personal Access Tokens ---")
	if len(pats) == 0 {
		fmt.Fprintln(w, "  No fine-grained PATs found.")
		return
	}

	headers := []string{"Owner", "Token Name", "Repo Access", "Permissions", "Expires", "Last Used", "Status"}
	var rows [][]string
	for _, p := range pats {
		status := "Active"
		if p.TokenExpired {
			status = "EXPIRED"
		}
		expires := "Never"
		if p.TokenExpiresAt != nil {
			expires = p.TokenExpiresAt.Format("2006-01-02")
		}
		lastUsed := "Never"
		if p.TokenLastUsedAt != nil {
			lastUsed = p.TokenLastUsedAt.Format("2006-01-02")
		}
		rows = append(rows, []string{
			p.OwnerLogin,
			p.TokenName,
			p.RepositorySelection,
			formatPermissions(p.Permissions),
			expires,
			lastUsed,
			status,
		})
	}
	printTable(w, headers, rows)
}

func renderAppsTable(w io.Writer, apps []models.AppInstallation) {
	fmt.Fprintln(w, "--- Installed GitHub Apps ---")
	if len(apps) == 0 {
		fmt.Fprintln(w, "  No installed apps found.")
		return
	}

	headers := []string{"App Name", "Repo Access", "High", "Med", "Low", "Events", "Installed", "Status"}
	var rows [][]string
	for _, a := range apps {
		status := "Active"
		if a.Suspended {
			status = "Suspended"
		}
		events := strings.Join(a.Events, ", ")
		if len(events) > 40 {
			events = events[:37] + "..."
		}
		rows = append(rows, []string{
			a.AppName,
			a.RepositorySelection,
			fmt.Sprintf("%d", a.HighRiskCount),
			fmt.Sprintf("%d", a.MediumRiskCount),
			fmt.Sprintf("%d", a.LowRiskCount),
			events,
			a.CreatedAt.Format("2006-01-02"),
			status,
		})
	}
	printTable(w, headers, rows)
}

func renderPendingTable(w io.Writer, requests []models.PATRequest) {
	fmt.Fprintln(w, "--- Pending PAT Requests ---")

	headers := []string{"Owner", "Token Name", "Repo Access", "Permissions", "Requested"}
	var rows [][]string
	for _, r := range requests {
		rows = append(rows, []string{
			r.OwnerLogin,
			r.TokenName,
			r.RepositorySelection,
			formatPermissions(r.Permissions),
			r.CreatedAt.Format("2006-01-02"),
		})
	}
	printTable(w, headers, rows)
}

func renderSSOTable(w io.Writer, creds []models.SSOCredential) {
	fmt.Fprintln(w, "--- SSO Authorized Credentials (Classic PATs & SSH Keys) ---")

	headers := []string{"Owner", "Type", "Title", "Token (last 8)", "Scopes", "Authorized", "Last Accessed", "Expires"}
	var rows [][]string
	for _, c := range creds {
		lastAccessed := "Never"
		if c.CredentialAccessedAt != nil {
			lastAccessed = c.CredentialAccessedAt.Format("2006-01-02")
		}
		expires := "Never"
		if c.AuthorizedCredentialExpAt != nil {
			expires = c.AuthorizedCredentialExpAt.Format("2006-01-02")
		}
		identifier := c.TokenLastEight
		if c.Fingerprint != "" {
			identifier = c.Fingerprint
			if len(identifier) > 16 {
				identifier = identifier[:16] + "..."
			}
		}
		scopes := strings.Join(c.Scopes, ", ")
		if len(scopes) > 40 {
			scopes = scopes[:37] + "..."
		}
		rows = append(rows, []string{
			c.Login,
			c.CredentialType,
			c.AuthorizedCredentialTitle,
			identifier,
			scopes,
			c.CredentialAuthorizedAt.Format("2006-01-02"),
			lastAccessed,
			expires,
		})
	}
	printTable(w, headers, rows)
}

func formatPermissions(perms []models.Permission) string {
	if len(perms) == 0 {
		return "none"
	}
	var parts []string
	for _, p := range perms {
		parts = append(parts, fmt.Sprintf("%s:%s", p.Name, p.Level))
	}
	result := strings.Join(parts, ", ")
	if len(result) > 60 {
		return result[:57] + "..."
	}
	return result
}

// printTable renders a simple aligned table.
func printTable(w io.Writer, headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
				if widths[i] > 50 {
					widths[i] = 50
				}
			}
		}
	}

	// Print header
	printRow(w, headers, widths)
	// Print separator
	var sep []string
	for _, width := range widths {
		sep = append(sep, strings.Repeat("-", width))
	}
	printRow(w, sep, widths)
	// Print rows
	for _, row := range rows {
		printRow(w, row, widths)
	}
}

func printRow(w io.Writer, cells []string, widths []int) {
	for i, cell := range cells {
		if i < len(widths) {
			fmt.Fprintf(w, "%-*s", widths[i]+2, cell)
		}
	}
	fmt.Fprintln(w)
}
