package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// zizmorTimeout bounds the offline analysis of the whole workflow tree.
const zizmorTimeout = 3 * time.Minute

// zizmorReport mirrors the subset of zizmor's `--format json` schema we use.
// Each finding carries its rule ident, docs URL, determinations, and a list of
// locations whose symbolic key holds the analyzed file path.
type zizmorReport []struct {
	Ident          string `json:"ident"`
	Desc           string `json:"desc"`
	URL            string `json:"url"`
	Determinations struct {
		Confidence string `json:"confidence"`
		Severity   string `json:"severity"`
	} `json:"determinations"`
	Locations []struct {
		Symbolic struct {
			Key struct {
				Local struct {
					GivenPath string `json:"given_path"`
				} `json:"Local"`
			} `json:"key"`
			Kind string `json:"kind"`
		} `json:"symbolic"`
		Concrete struct {
			Location struct {
				StartPoint struct {
					Row int `json:"row"` // 0-based
				} `json:"start_point"`
			} `json:"location"`
		} `json:"concrete"`
	} `json:"locations"`
}

// RunZizmor writes the fetched workflow YAMLs to a temp tree, runs zizmor
// offline over them, and returns findings keyed by "<repo>|<path>" so callers
// can attach them to the matching models.WorkflowFile.
//
// zizmor exits non-zero when it finds issues, so the exit status is ignored;
// only an empty stdout combined with a non-zero exit is treated as a failure.
// A missing zizmor binary degrades gracefully (logs a warning, returns nil).
func RunZizmor(ctx context.Context, contents []ghservice.WorkflowContent) (map[string][]models.ZizmorFinding, error) {
	if len(contents) == 0 {
		return nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "zizmor-*")
	if err != nil {
		return nil, fmt.Errorf("zizmor: temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Lay out files as <tmp>/<repo>/<path> so the file path zizmor echoes back
	// uniquely identifies the repo + workflow even when filenames collide.
	for _, c := range contents {
		dst := filepath.Join(tmpDir, c.RepoName, filepath.FromSlash(c.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, fmt.Errorf("zizmor: mkdir: %w", err)
		}
		if err := os.WriteFile(dst, []byte(c.Content), 0o644); err != nil {
			return nil, fmt.Errorf("zizmor: write %s: %w", dst, err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, zizmorTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zizmor",
		"--offline", "--format", "json", "--min-severity", "low", tmpDir)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	out := strings.TrimSpace(stdout.String())

	if runErr != nil {
		if errors.Is(runErr, exec.ErrNotFound) {
			log.Printf("WARNING: zizmor binary not found; skipping workflow SAST")
			return nil, nil
		}
		// Findings present → non-zero exit with valid JSON on stdout. Only a
		// non-zero exit with NO output is a real failure.
		if out == "" {
			return nil, fmt.Errorf("zizmor run failed: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
	}

	return parseZizmorOutput([]byte(out), tmpDir)
}

// parseZizmorOutput decodes zizmor JSON and maps findings back to "<repo>|<path>"
// keys by stripping the temp-dir prefix from each finding's file path.
func parseZizmorOutput(data []byte, tmpDir string) (map[string][]models.ZizmorFinding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var report zizmorReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("zizmor: parse json: %w", err)
	}

	out := map[string][]models.ZizmorFinding{}
	prefix := tmpDir + string(os.PathSeparator)

	for _, f := range report {
		key, line := "", 0
		for _, loc := range f.Locations {
			p := loc.Symbolic.Key.Local.GivenPath
			if p == "" {
				continue
			}
			rel := strings.TrimPrefix(p, prefix)
			repo, path, ok := strings.Cut(filepath.ToSlash(rel), "/")
			if !ok {
				continue
			}
			key = repo + "|" + path
			line = loc.Concrete.Location.StartPoint.Row + 1 // 0-based → 1-based
			if loc.Symbolic.Kind == "Primary" {
				break // prefer the primary location
			}
		}
		if key == "" {
			continue
		}
		out[key] = append(out[key], models.ZizmorFinding{
			RuleID:     f.Ident,
			Desc:       f.Desc,
			URL:        f.URL,
			Severity:   strings.ToLower(f.Determinations.Severity),
			Confidence: strings.ToLower(f.Determinations.Confidence),
			Line:       line,
		})
	}
	return out, nil
}
