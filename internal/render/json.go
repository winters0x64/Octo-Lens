package render

import (
	"encoding/json"
	"io"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

func RenderJSON(w io.Writer, report *models.OrgReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
