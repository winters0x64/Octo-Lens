package scanner

import "testing"

// Fixture mirrors zizmor 1.5.2 `--format json` output (path + 0-based row +
// capitalized severity), with the temp prefix the scanner writes under.
const zizmorJSON = `[
  {
    "ident": "template-injection",
    "desc": "code injection via template expansion",
    "url": "https://docs.zizmor.sh/audits/#template-injection",
    "determinations": { "confidence": "High", "severity": "High", "persona": "Regular" },
    "locations": [
      { "symbolic": { "key": { "Local": { "given_path": "/tmp/zizmor-123/payments-service/.github/workflows/ci.yml" } }, "kind": "Primary" },
        "concrete": { "location": { "start_point": { "row": 11, "column": 8 } } } }
    ]
  },
  {
    "ident": "artipacked",
    "desc": "credential persistence through artifacts",
    "url": "https://docs.zizmor.sh/audits/#artipacked",
    "determinations": { "confidence": "Low", "severity": "Medium", "persona": "Regular" },
    "locations": [
      { "symbolic": { "key": { "Local": { "given_path": "/tmp/zizmor-123/acme-backend/.github/workflows/deploy.yml" } }, "kind": "Primary" },
        "concrete": { "location": { "start_point": { "row": 7, "column": 8 } } } }
    ]
  }
]`

func TestParseZizmorOutput(t *testing.T) {
	got, err := parseZizmorOutput([]byte(zizmorJSON), "/tmp/zizmor-123")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	ci := got["payments-service|.github/workflows/ci.yml"]
	if len(ci) != 1 {
		t.Fatalf("expected 1 finding for ci.yml, got %d", len(ci))
	}
	f := ci[0]
	if f.RuleID != "template-injection" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if f.Severity != "high" { // lowercased from "High"
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Line != 12 { // 0-based row 11 → 1-based 12
		t.Errorf("line = %d, want 12", f.Line)
	}

	dep := got["acme-backend|.github/workflows/deploy.yml"]
	if len(dep) != 1 || dep[0].Severity != "medium" {
		t.Errorf("deploy.yml finding wrong: %+v", dep)
	}
}

func TestParseZizmorEmpty(t *testing.T) {
	got, err := parseZizmorOutput(nil, "/tmp/x")
	if err != nil || got != nil {
		t.Errorf("empty input should yield (nil, nil); got %v, %v", got, err)
	}
}
