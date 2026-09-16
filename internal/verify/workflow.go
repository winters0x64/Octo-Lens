package verify

import (
	"fmt"
	"strings"
)

// EnvironmentSecrets groups the secret names that live in one specific GitHub
// Environment. GitHub only resolves ${{ secrets.NAME }} to an environment
// secret when the job declares `environment: <name>` — without that, the
// reference silently resolves to an empty string rather than erroring, so
// each environment needs its own job in the generated workflow.
type EnvironmentSecrets struct {
	EnvName string
	Names   []string
}

// GenerateWorkflow produces a GitHub Actions workflow YAML that verifies
// every secret in the repo in-place: repo-level secrets in one job, and one
// additional job per environment (each scoped via `environment:` so its
// secrets actually resolve). Instead of guessing the provider from the
// secret name, each secret's VALUE is pattern-matched at runtime:
//   - Starts with AKIA/ASIA           → AWS access key    → sts get-caller-identity
//   - Starts with ghp_/gho_/github_pat_ → GitHub PAT       → /user API
//   - Starts with sk-ant-api03-       → Anthropic key     → /v1/models
//   - Starts with sk- (not sk-ant-)   → OpenAI key        → /v1/models
//   - Starts with sk_live_/sk_test_/rk_live_/rk_test_ → Stripe key → /v1/balance
//   - Starts with xoxb-               → Slack bot token   → auth.test
//   - Starts with AIzaSy              → Google/Gemini key → generativelanguage models
//   - Starts with npm_                → npm token         → registry whoami
//   - Starts with squ_/sqa_           → SonarCloud token  → authentication/validate
//   - Otherwise                       → skip (unverifiable)
//
// Providers whose tokens have no distinctive value prefix (PagerDuty, Cloudinary,
// Databricks, self-hosted SonarQube, ...) aren't covered here — matching them
// reliably needs cross-referencing a paired secret (e.g. a host/cloud-name secret)
// rather than pattern-matching the value alone, which this generator doesn't do yet.
func GenerateWorkflow(repoFullName string, repoSecrets []string, envGroups []EnvironmentSecrets) string {
	var jobs []string
	var jobIDs []string

	if len(repoSecrets) > 0 {
		jobIDs = append(jobIDs, "verify")
		jobs = append(jobs, buildJob("verify", "", repoSecrets, "octolens-verify"))
	}
	for i, g := range envGroups {
		if len(g.Names) == 0 {
			continue
		}
		jobID := fmt.Sprintf("verify-env-%d", i)
		artifactName := fmt.Sprintf("octolens-verify-env-%d", i)
		jobIDs = append(jobIDs, jobID)
		jobs = append(jobs, buildJob(jobID, g.EnvName, g.Names, artifactName))
	}

	return fmt.Sprintf(`name: octolens-secret-verify
on: push

permissions:
  contents: read

jobs:
%s
`, strings.Join(jobs, "\n"))
}

// buildJob renders one job that verifies secretNames. When envName is
// non-empty, the job declares `environment: <envName>` so that
// ${{ secrets.NAME }} resolves that environment's secrets rather than
// silently resolving to empty — and every recorded result is tagged with
// that environment name so callers can tell which environment's copy of a
// (possibly same-named) secret a result belongs to.
func buildJob(jobID, envName string, secretNames []string, artifactName string) string {
	envLines := make([]string, 0, len(secretNames))
	for _, s := range secretNames {
		envLines = append(envLines, fmt.Sprintf("          %s: ${{ secrets.%s }}", s, s))
	}

	environmentLine := ""
	if envName != "" {
		environmentLine = fmt.Sprintf("    environment: %q\n", envName)
	}

	detectStep := fmt.Sprintf(`      - name: Detect and verify secrets
        continue-on-error: true
        run: |
          # GitHub Actions runs bash steps with -e -o pipefail by default — any
          # unguarded failing command (e.g. an AWS IAM call denied for this
          # credential's permissions, producing no stdout for jq to parse)
          # would otherwise abort this ENTIRE script immediately, silently
          # dropping every secret check that hadn't already been recorded yet.
          # This script's own control flow already handles expected failures
          # explicitly via &&/||/if throughout, so disable errexit to restore
          # the semantics it was actually written for.
          set +e
          set +o pipefail

          ENV_NAME=%q

          # Detect AWS credentials: find every access key ID (AKIA/ASIA prefix),
          # then pair each with its secret key. A single batch can contain
          # MULTIPLE unrelated AWS credential sets at once (e.g. an org-wide
          # sweep mixing AWS_ACCESS_KEY_ID, _BETA, and _PROD together) — pairing
          # by loop position instead of by name would silently mismatch a key ID
          # against the wrong secret value, since bash has no notion of which
          # two secrets "belong together" beyond their names. Match by the
          # AWS_ACCESS_KEY_ID<suffix> / AWS_SECRET_ACCESS_KEY<suffix> naming
          # convention first, falling back to positional pairing only when a
          # name-based match isn't available (e.g. non-standard names).
          declare -A AWS_KEYID_VALS AWS_SECRET_VALS AWS_CLAIMED
          AWS_SESSION_NAME=""
          AWS_SESSION_VAL=""

          for secret_name in %s; do
            VAL="${!secret_name}"
            [ -z "$VAL" ] && continue

            # AWS access key ID always starts with AKIA (long-term) or ASIA (session)
            if echo "$VAL" | grep -qE '^A[KS]IA[A-Z0-9]{16}$'; then
              AWS_KEYID_VALS["$secret_name"]="$VAL"
              continue
            fi

            # AWS secret access key is 40 chars base64-ish
            if [ ${#VAL} -eq 40 ]; then
              AWS_SECRET_VALS["$secret_name"]="$VAL"
              continue
            fi

            # AWS session token (long base64 string, typically 300+ chars).
            # Only one is supported per batch — session/temporary credentials
            # mixed with multiple unrelated long-term key pairs in one batch
            # is not a case seen in practice.
            if echo "$secret_name" | grep -qi "SESSION_TOKEN\|SESSION\|STS_TOKEN"; then
              AWS_SESSION_NAME="$secret_name"
              AWS_SESSION_VAL="$VAL"
              continue
            fi
            # Also detect by value: session tokens start with IQoJ or FwoG
            if [ ${#VAL} -gt 200 ] && echo "$VAL" | grep -qE '^(IQoJ|FwoG)'; then
              AWS_SESSION_NAME="$secret_name"
              AWS_SESSION_VAL="$VAL"
              continue
            fi
          done

          for AWS_KEY_ID_NAME in "${!AWS_KEYID_VALS[@]}"; do
            AWS_KEY_ID_VAL="${AWS_KEYID_VALS[$AWS_KEY_ID_NAME]}"
            AWS_SECRET_NAME=""

            # Preferred: exact naming-convention match.
            CANDIDATE_NAME="${AWS_KEY_ID_NAME/ACCESS_KEY_ID/SECRET_ACCESS_KEY}"
            if [ "$CANDIDATE_NAME" != "$AWS_KEY_ID_NAME" ] && [ -n "${AWS_SECRET_VALS[$CANDIDATE_NAME]+set}" ] && [ -z "${AWS_CLAIMED[$CANDIDATE_NAME]+set}" ]; then
              AWS_SECRET_NAME="$CANDIDATE_NAME"
            fi

            # Fallback: any not-yet-claimed 40-char candidate (covers
            # non-standard naming — this is exactly the old behavior, just
            # only used when a proper name match isn't available).
            if [ -z "$AWS_SECRET_NAME" ]; then
              for cand in "${!AWS_SECRET_VALS[@]}"; do
                if [ -z "${AWS_CLAIMED[$cand]+set}" ]; then
                  AWS_SECRET_NAME="$cand"
                  break
                fi
              done
            fi

            AWS_CLAIMED["$AWS_KEY_ID_NAME"]=1

            if [ -n "$AWS_SECRET_NAME" ]; then
              AWS_CLAIMED["$AWS_SECRET_NAME"]=1
              AWS_SECRET_VAL="${AWS_SECRET_VALS[$AWS_SECRET_NAME]}"

              export AWS_ACCESS_KEY_ID="$AWS_KEY_ID_VAL"
              export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_VAL"
              # Session credentials (ASIA prefix) need the session token
              if [ -n "$AWS_SESSION_VAL" ]; then
                export AWS_SESSION_TOKEN="$AWS_SESSION_VAL"
              fi
              pip install -q awscli > /dev/null 2>&1
              RESULT=$(aws sts get-caller-identity 2>&1) && VALID=true || VALID=false
              if $VALID; then
                ARN=$(echo "$RESULT" | jq -r '.Arn')
                USER_NAME=$(echo "$ARN" | grep -oP '(?<=user/).*' || echo "")
                POLICIES="[]"
                LAST_USED=""
                PERMISSION_NOTES="[]"
                if [ -n "$USER_NAME" ]; then
                  # A denied/failed IAM call can print nothing to stdout at all
                  # rather than an error JSON body — piping zero bytes into jq
                  # succeeds (exit 0, no output) rather than failing, so the
                  # "|| echo" fallback never fires and the variable is left
                  # truly empty. Explicitly re-check for that after each call.
                  ATTACHED_JSON=$(aws iam list-attached-user-policies --user-name "$USER_NAME" 2>/dev/null)
                  POLICIES=$(echo "$ATTACHED_JSON" | jq -c '[.AttachedPolicies[].PolicyName]' 2>/dev/null)
                  [ -z "$POLICIES" ] && POLICIES="[]"
                  INLINE=$(aws iam list-user-policies --user-name "$USER_NAME" 2>/dev/null | jq -c '.PolicyNames' 2>/dev/null)
                  [ -z "$INLINE" ] && INLINE="[]"
                  ALL_POLICY_NAMES=$(echo "[$POLICIES, $INLINE]" | jq -c 'flatten' 2>/dev/null)
                  [ -z "$ALL_POLICY_NAMES" ] && ALL_POLICY_NAMES="[]"
                  POLICIES="$ALL_POLICY_NAMES"
                  LAST_USED=$(aws iam get-access-key-last-used --access-key-id "$AWS_ACCESS_KEY_ID" 2>/dev/null | jq -r '.AccessKeyLastUsed.LastUsedDate // empty' 2>/dev/null)

                  # Determine what this credential can actually DO, not just
                  # which policy names are attached — a custom policy name like
                  # "cdk-deploy-custome-permissions" reveals nothing on its own.
                  # Prefer asking AWS itself to evaluate (iam:SimulatePrincipalPolicy
                  # — accounts for explicit denies etc.), since that's more
                  # accurate than re-implementing policy evaluation ourselves. A
                  # narrowly-scoped (i.e. well-designed) credential often won't
                  # have permission to simulate itself though, so fall back to
                  # fetching the actual policy documents and scanning them for
                  # wildcard/dangerous grants.
                  DANGEROUS_ACTIONS="iam:CreateUser iam:AttachUserPolicy iam:PutUserPolicy iam:CreateAccessKey iam:AttachRolePolicy iam:PassRole sts:AssumeRole organizations:LeaveOrganization s3:GetObject ec2:RunInstances lambda:InvokeFunction kms:Decrypt"
                  SIM=$(aws iam simulate-principal-policy --policy-source-arn "$ARN" --action-names $DANGEROUS_ACTIONS 2>/dev/null)
                  SIM_NOTES="[]"
                  if [ -n "$SIM" ]; then
                    SIM_NOTES=$(echo "$SIM" | jq -c '[.EvaluationResults[]? | select(.EvalDecision=="allowed") | ("simulate:" + .EvalActionName + "=allowed")]' 2>/dev/null)
                    [ -z "$SIM_NOTES" ] && SIM_NOTES="[]"
                  fi

                  DOC_NOTES="[]"
                  if [ "$SIM_NOTES" = "[]" ]; then
                    for parn in $(echo "$ATTACHED_JSON" | jq -r '.AttachedPolicies[]?.PolicyArn' 2>/dev/null); do
                      pname=$(echo "$parn" | grep -oP '[^/]+$')
                      pversion=$(aws iam get-policy --policy-arn "$parn" 2>/dev/null | jq -r '.Policy.DefaultVersionId // empty' 2>/dev/null)
                      [ -z "$pversion" ] && continue
                      pdoc=$(aws iam get-policy-version --policy-arn "$parn" --version-id "$pversion" 2>/dev/null | jq -c '.PolicyVersion.Document' 2>/dev/null)
                      [ -z "$pdoc" ] && continue
                      haswild=$(echo "$pdoc" | jq -r '[.Statement[]? | select(.Effect=="Allow") | .Action] | flatten | map(select(. == "*" or . == "iam:*" or . == "sts:AssumeRole" or . == "organizations:*")) | length > 0' 2>/dev/null)
                      if [ "$haswild" = "true" ]; then
                        DOC_NOTES=$(echo "$DOC_NOTES" | jq -c --arg n "wildcard-policy:$pname" '. += [$n]' 2>/dev/null)
                        [ -z "$DOC_NOTES" ] && DOC_NOTES="[]"
                      fi
                    done
                    for pname in $(echo "$INLINE" | jq -r '.[]?' 2>/dev/null); do
                      pdoc=$(aws iam get-user-policy --user-name "$USER_NAME" --policy-name "$pname" 2>/dev/null | jq -c '.PolicyDocument' 2>/dev/null)
                      [ -z "$pdoc" ] && continue
                      haswild=$(echo "$pdoc" | jq -r '[.Statement[]? | select(.Effect=="Allow") | .Action] | flatten | map(select(. == "*" or . == "iam:*" or . == "sts:AssumeRole" or . == "organizations:*")) | length > 0' 2>/dev/null)
                      if [ "$haswild" = "true" ]; then
                        DOC_NOTES=$(echo "$DOC_NOTES" | jq -c --arg n "wildcard-policy:$pname" '. += [$n]' 2>/dev/null)
                        [ -z "$DOC_NOTES" ] && DOC_NOTES="[]"
                      fi
                    done
                  fi

                  # A well-known dangerous MANAGED policy name is a strong, cheap
                  # signal on its own — record it even if the checks above were
                  # inconclusive (e.g. a policy version fetch failed).
                  KNOWN_ADMIN=$(echo "$POLICIES" | jq -c '[.[] | select(. == "AdministratorAccess" or . == "PowerUserAccess" or . == "IAMFullAccess")] | map("managed-policy:" + .)' 2>/dev/null)
                  [ -z "$KNOWN_ADMIN" ] && KNOWN_ADMIN="[]"

                  PERMISSION_NOTES=$(echo "[$SIM_NOTES, $DOC_NOTES, $KNOWN_ADMIN]" | jq -c 'flatten' 2>/dev/null)
                  [ -z "$PERMISSION_NOTES" ] && PERMISSION_NOTES="[]"
                fi
                AWS_NAMES="$AWS_KEY_ID_NAME $AWS_SECRET_NAME"
                [ -n "$AWS_SESSION_NAME" ] && AWS_NAMES="$AWS_NAMES $AWS_SESSION_NAME"
                for sn in $AWS_NAMES; do
                  jq --arg n "$sn" --arg arn "$ARN" --argjson perms "$POLICIES" --arg lu "$LAST_USED" --arg env "$ENV_NAME" --argjson notes "$PERMISSION_NOTES" \
                    '. += [{"name":$n,"provider":"aws","valid":true,"recognized":true,"identity":$arn,"permissions":$perms,"last_used":$lu,"environment":$env,"permission_notes":$notes}]' \
                    /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
                done
              else
                ERR=$(echo "$RESULT" | head -1)
                [ -z "$ERR" ] && ERR="aws sts get-caller-identity failed with no output (invalid credentials, or aws CLI itself failed to run)"
                AWS_NAMES="$AWS_KEY_ID_NAME $AWS_SECRET_NAME"
                [ -n "$AWS_SESSION_NAME" ] && AWS_NAMES="$AWS_NAMES $AWS_SESSION_NAME"
                for sn in $AWS_NAMES; do
                  jq --arg n "$sn" --arg e "$ERR" --arg env "$ENV_NAME" \
                    '. += [{"name":$n,"provider":"aws","valid":false,"recognized":true,"error":$e,"environment":$env}]' \
                    /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
                done
              fi
              unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
            else
              # Found this access key but no secret key left to pair it with
              jq --arg n "$AWS_KEY_ID_NAME" --arg env "$ENV_NAME" \
                '. += [{"name":$n,"provider":"aws","valid":false,"recognized":true,"error":"access key found but no matching secret key","environment":$env}]' \
                /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
            fi
          done

          # record_valid $1=name $2=provider $3=identity $4=permissions(JSON array)
          # record_invalid $1=name $2=provider $3=error
          # record_unrecognized $1=name — value didn't match ANY known credential
          # format, so we have no idea if it's live or dead (NOT the same as
          # record_invalid, which means we checked against a real provider and
          # got a definitive "dead" answer).
          record_valid() {
            jq --arg n "$1" --arg p "$2" --arg id "$3" --argjson perms "$4" --arg env "$ENV_NAME" \
              '. += [{"name":$n,"provider":$p,"valid":true,"recognized":true,"identity":$id,"permissions":$perms,"environment":$env}]' \
              /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
          }
          record_invalid() {
            jq --arg n "$1" --arg p "$2" --arg e "$3" --arg env "$ENV_NAME" \
              '. += [{"name":$n,"provider":$p,"valid":false,"recognized":true,"error":$e,"environment":$env}]' \
              /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
          }
          record_unrecognized() {
            jq --arg n "$1" --arg env "$ENV_NAME" \
              '. += [{"name":$n,"provider":"unknown","valid":false,"recognized":false,"error":"no verifiable credential pattern detected","environment":$env}]' \
              /tmp/verify-results.json > /tmp/vr.json && mv /tmp/vr.json /tmp/verify-results.json
          }

          # Now check each remaining secret against known value patterns
          for secret_name in %s; do
            [ -n "${AWS_CLAIMED[$secret_name]+set}" ] && continue
            [ "$secret_name" = "$AWS_SESSION_NAME" ] && continue
            VAL="${!secret_name}"
            [ -z "$VAL" ] && continue

            if echo "$VAL" | grep -qE '^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)'; then
              # GitHub PAT: classic (ghp_), OAuth (gho_), fine-grained (github_pat_)
              RESP=$(curl -sf -H "Authorization: token $VAL" https://api.github.com/user 2>&1) && VALID=true || VALID=false
              if $VALID; then
                LOGIN=$(echo "$RESP" | jq -r '.login')
                # Anchor to the start of the line and strip CRLF: an unanchored match also
                # hits the unrelated access-control-expose-headers line, which lists
                # "X-OAuth-Scopes" as one of many header *names* it exposes via CORS —
                # that polluted the reported scopes with the entire header-name list.
                SCOPES=$(curl -sI -H "Authorization: token $VAL" https://api.github.com/user | tr -d '\r' | grep -i '^x-oauth-scopes:' | cut -d: -f2- | xargs)
                record_valid "$secret_name" "github" "$LOGIN" "$(echo "$SCOPES" | jq -R 'split(", ") | map(select(length > 0))')"
              else
                record_invalid "$secret_name" "github" "invalid or expired token"
              fi

            elif echo "$VAL" | grep -qE '^sk-ant-api03-'; then
              # Anthropic API key
              curl -sf https://api.anthropic.com/v1/models \
                -H "x-api-key: $VAL" -H "anthropic-version: 2023-06-01" >/tmp/resp.json 2>&1 && VALID=true || VALID=false
              if $VALID; then
                record_valid "$secret_name" "anthropic" "valid API key" "[]"
              else
                record_invalid "$secret_name" "anthropic" "invalid or revoked key"
              fi

            elif echo "$VAL" | grep -qE '^sk-'; then
              # OpenAI API key (legacy sk-... and sk-proj-...)
              curl -sf https://api.openai.com/v1/models -H "Authorization: Bearer $VAL" >/tmp/resp.json 2>&1 && VALID=true || VALID=false
              if $VALID; then
                ORG=$(curl -sI https://api.openai.com/v1/models -H "Authorization: Bearer $VAL" | grep -i 'openai-organization' | cut -d: -f2- | xargs)
                record_valid "$secret_name" "openai" "$ORG" "[]"
              else
                record_invalid "$secret_name" "openai" "invalid or revoked key"
              fi

            elif echo "$VAL" | grep -qE '^(sk|rk)_(live|test)_'; then
              # Stripe secret/restricted key
              RESP=$(curl -sf https://api.stripe.com/v1/balance -u "$VAL:" 2>&1) && VALID=true || VALID=false
              if $VALID; then
                LIVEMODE=$(echo "$RESP" | jq -r 'if .livemode then "live mode" else "test mode" end')
                record_valid "$secret_name" "stripe" "$LIVEMODE" "[]"
              else
                record_invalid "$secret_name" "stripe" "invalid or revoked key"
              fi

            elif echo "$VAL" | grep -qE '^xoxb-'; then
              # Slack bot token
              RESP=$(curl -s https://slack.com/api/auth.test -H "Authorization: Bearer $VAL")
              OK=$(echo "$RESP" | jq -r '.ok')
              if [ "$OK" = "true" ]; then
                TEAM=$(echo "$RESP" | jq -r '.team // empty')
                USER=$(echo "$RESP" | jq -r '.user // .bot_id // empty')
                # Slack's API only reports OAuth scopes via this response header
                # for classic (non-granular) apps — modern granular-scope bot
                # tokens won't have it, so this legitimately comes back empty
                # for most current tokens; that's an honest "unknown", not a bug.
                SLACK_SCOPES=$(curl -sI https://slack.com/api/auth.test -H "Authorization: Bearer $VAL" | tr -d '\r' | grep -i '^x-oauth-scopes:' | cut -d: -f2- | xargs)
                record_valid "$secret_name" "slack" "$TEAM / $USER" "$(echo "$SLACK_SCOPES" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length > 0))')"
              else
                ERR=$(echo "$RESP" | jq -r '.error // "invalid_auth"')
                record_invalid "$secret_name" "slack" "$ERR"
              fi

            elif echo "$VAL" | grep -qE '^AIzaSy'; then
              # Google AI Studio / Gemini API key
              curl -sf "https://generativelanguage.googleapis.com/v1beta/models?key=$VAL" >/tmp/resp.json 2>&1 && VALID=true || VALID=false
              if $VALID; then
                record_valid "$secret_name" "gemini" "valid API key" "[]"
              else
                record_invalid "$secret_name" "gemini" "invalid or revoked key"
              fi

            elif echo "$VAL" | grep -qE '^npm_'; then
              # npm access token (registry.npmjs.org only)
              RESP=$(curl -sf https://registry.npmjs.org/-/whoami -H "Authorization: Bearer $VAL" 2>&1) && VALID=true || VALID=false
              if $VALID; then
                USERNAME=$(echo "$RESP" | jq -r '.username // empty')
                record_valid "$secret_name" "npm" "$USERNAME" "[]"
              else
                record_invalid "$secret_name" "npm" "invalid or revoked token"
              fi

            elif echo "$VAL" | grep -qE '^(squ_|sqa_)'; then
              # SonarCloud token (self-hosted SonarQube tokens have no distinctive prefix and aren't covered)
              RESP=$(curl -s -u "$VAL:" https://sonarcloud.io/api/authentication/validate)
              VALIDFLAG=$(echo "$RESP" | jq -r '.valid // false')
              if [ "$VALIDFLAG" = "true" ]; then
                record_valid "$secret_name" "sonarcloud" "valid token" "[]"
              else
                record_invalid "$secret_name" "sonarcloud" "invalid or revoked token"
              fi

            else
              record_unrecognized "$secret_name"
            fi
          done
        env:
%s`, envName, shellQuotedList(secretNames), shellQuotedList(secretNames), strings.Join(envLines, "\n"))

	return fmt.Sprintf(`  %s:
    runs-on: ubuntu-latest
%s    steps:
      - name: Init results
        run: echo '[]' > /tmp/verify-results.json
%s
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: %s
          path: /tmp/verify-results.json
          retention-days: 1
`, jobID, environmentLine, detectStep, artifactName)
}

func shellQuotedList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(quoted, " ")
}
