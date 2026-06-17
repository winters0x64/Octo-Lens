package graph

import (
	"regexp"
	"strings"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// SecretClass is the inferred meaning of an Actions secret. It drives both the
// secret's risk weight and whether it is a *production boundary*: a long-lived
// credential to external SaaS/infra that a supply-chain-compromised job could
// exfiltrate and reuse directly. Unlike a federated OIDC token (short-lived,
// sub-scoped), these are durable loot — so reaching one is itself a path to prod.
type SecretClass struct {
	Category    string // machine key, e.g. "aws_static"
	Provider    string // human label, e.g. "AWS static key"
	Target      string // pivot target, e.g. "AWS account"
	Criticality string // critical | high | medium | low
	Boundary    bool   // counts as a path-to-production boundary
	LongLived   bool   // static / non-expiring credential (worse than OIDC)
}

type secretRule struct {
	re  *regexp.Regexp
	cls SecretClass
}

// Obvious non-secret values (identifiers, regions, public config) — never a
// boundary, low weight. Checked before the rules; _URL is intentionally NOT here
// so DATABASE_URL / connection strings still classify as DB credentials.
var secretNonSensitiveRe = regexp.MustCompile(`(?i)(^|_)(IDS?|ALIAS|USERNAMES?|USER|REGION|ZONE|PROJECT|ORG|ACCOUNT_ID|CHANNEL_ID|HOST|HOSTNAME|ENDPOINT|EMAIL|ARN|NAME|VERSION|PATH|DIR|ENABLED?)$`)
var secretPublicRe = regexp.MustCompile(`(?i)(^|_)(PUBLIC|NEXT_PUBLIC)`)

// b is shorthand for a boundary class (long-lived external credential).
func bcls(cat, provider, target, crit string) SecretClass {
	return SecretClass{Category: cat, Provider: provider, Target: target, Criticality: crit, Boundary: true, LongLived: true}
}

// Ordered: first match wins, most specific/highest-value first.
var secretRules = []secretRule{
	// Cloud provider static credentials — long-lived, no expiry, no sub scoping;
	// strictly worse than the OIDC role the graph already treats as a crown jewel.
	{regexp.MustCompile(`(?i)AWS.*(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SECRET_KEY|SESSION_TOKEN)`), bcls("aws_static", "AWS static key", "AWS account", "critical")},
	{regexp.MustCompile(`(?i)(GCP|GOOGLE).*(SA_KEY|SERVICE_ACCOUNT|CREDENTIALS|PRIVATE_KEY|_KEY$)`), bcls("gcp_sa", "GCP service-account key", "GCP project", "critical")},
	{regexp.MustCompile(`(?i)AZURE.*(CREDENTIALS|CLIENT_SECRET|SECRET|PASSWORD)`), bcls("azure", "Azure credential", "Azure subscription", "critical")},
	// SSH / private keys — direct host/infra or signing access.
	{regexp.MustCompile(`(?i)(SSH.*(KEY|PRIVATE)|PRIVATE_KEY|_PEM$|_PKCS)`), bcls("ssh_key", "SSH / private key", "host / infrastructure", "critical")},
	// Code-signing & release material.
	{regexp.MustCompile(`(?i)(KEYSTORE.*(PASSWORD|STORE)|GPG|CODESIGN|SIGNING|DEXGUARD|GUARDSQUARE|PROVISIONING|\bP12\b)`), bcls("signing", "Code-signing key", "release / app signing", "critical")},
	// Package-registry publish tokens — supply-chain amplification downstream.
	{regexp.MustCompile(`(?i)(NPM.*TOKEN|PYPI|TWINE|DOCKER.*(PASSWORD|TOKEN|HUB)|DOCKERHUB|NUGET.*(KEY|TOKEN)|CARGO_REGISTRY|GEM_HOST|MAVEN.*(PASSWORD|TOKEN)|ARTIFACTORY|JFROG)`), bcls("publish_token", "Package-registry token", "package registry", "high")},
	// Database / datastore credentials.
	{regexp.MustCompile(`(?i)(DB|DATABASE|MYSQL|POSTGRES|PG|MONGO|REDIS|RDS|SNOWFLAKE|CLICKHOUSE).*(PASSWORD|URL|URI|DSN|CONNECTION|SECRET|CREDENTIAL)`), bcls("db_cred", "Database credential", "database", "high")},
	// Source-control tokens — pivot to more repos / the build system itself.
	{regexp.MustCompile(`(?i)((^|_)(GH|GHE|GITHUB)_.*(PAT|TOKEN)|_PAT$|GITLAB.*TOKEN|BITBUCKET.*(TOKEN|PASSWORD))`), bcls("vcs_token", "Source-control token", "source control (more repos)", "high")},
	// Hosting / deploy SaaS.
	{regexp.MustCompile(`(?i)(VERCEL_TOKEN|NETLIFY.*(TOKEN|AUTH)|CLOUDFLARE.*(TOKEN|API)|CF_API|FLY_API|HEROKU.*(API|TOKEN)|RAILWAY)`), bcls("saas_hosting", "Hosting/deploy token", "hosting platform", "high")},
	// Data / observability / other SaaS API keys.
	{regexp.MustCompile(`(?i)(DATABRICKS|SNOWFLAKE|STRIPE|DATADOG|DD_API|SENTRY|TWILIO|PAGERDUTY|NEWRELIC|GRAFANA|HONEYCOMB|OPENAI|ANTHROPIC|SONAR.*(TOKEN|PRIVATE_KEY|APP))`), bcls("saas_api", "SaaS API credential", "SaaS service", "high")},
}

// Lower-value but still credential-ish (not a boundary on their own).
var secretMediumRe = regexp.MustCompile(`(?i)(SLACK.*(WEBHOOK|TOKEN)|WEBHOOK|_TOKEN$|_SECRET$|_PASSWORD$|_PASSWD$|_PWD$|_KEY$|API_KEY|APIKEY)`)

// classifySecret infers a secret's class from its name (heuristic, no network).
func classifySecret(name string) SecretClass {
	n := strings.ToUpper(strings.TrimSpace(name))
	for _, r := range secretRules {
		if r.re.MatchString(n) {
			return r.cls
		}
	}
	if secretPublicRe.MatchString(n) || secretNonSensitiveRe.MatchString(n) {
		return SecretClass{Category: "config", Provider: "Config / identifier", Criticality: "low"}
	}
	if secretMediumRe.MatchString(n) {
		return SecretClass{Category: "credential", Provider: "Credential", Target: "unknown", Criticality: "medium"}
	}
	return SecretClass{Category: "unknown", Provider: "Secret", Criticality: "medium"}
}

var riskRankTbl = map[string]int{"high": 3, "medium": 2, "low": 1, "none": 0}

// secretNodeRisk combines the scope/visibility weight with the inferred
// criticality and returns the higher of the two.
func secretNodeRisk(s models.OrgSecret, cls SecretClass) string {
	base := secretRisk(s)
	crit := map[string]string{"critical": "high", "high": "high", "medium": "medium", "low": "low"}[cls.Criticality]
	if crit == "" {
		crit = "low"
	}
	if riskRankTbl[crit] > riskRankTbl[base] {
		return crit
	}
	return base
}
