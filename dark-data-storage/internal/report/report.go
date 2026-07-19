// Package report defines the per-object ledger record and the aggregate scan
// summary. The aggregate is reconstructable purely from a stream of Records, so
// it stays correct after a resumed run replays the existing ledger.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/engine"
)

// Record is one line of the append-only results ledger (results.jsonl). Every
// processed object produces exactly one Record — including clean ones, whose
// Findings slice is empty — so the ledger doubles as the resume checkpoint.
type Record struct {
	Key          string           `json:"key"`
	Size         int64            `json:"size"`
	BytesScanned int64            `json:"bytes_scanned"`
	Skipped      bool             `json:"skipped,omitempty"`
	SkipReason   string           `json:"skip_reason,omitempty"`
	Extracted    string           `json:"extracted,omitempty"`
	Error        string           `json:"error,omitempty"`
	Findings     []engine.Finding `json:"findings"`
	ScannedAt    time.Time        `json:"scanned_at"`
}

// Report is the aggregate summary. Its methods are safe for concurrent use.
type Report struct {
	mu sync.Mutex

	Bucket      string    `json:"bucket"`
	Prefix      string    `json:"prefix"`
	Region      string    `json:"region"`
	SameAccount string    `json:"same_account"` // "yes" | "no" | "unknown"
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Complete    bool      `json:"complete"`
	ResultsFile string    `json:"results_file"`

	ScannedObjects int            `json:"scanned_objects"`
	SkippedObjects int            `json:"skipped_objects"`
	ErrorObjects   int            `json:"error_objects"`
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
}

// New creates an empty aggregate.
func New(bucket, prefix, region string) *Report {
	return &Report{
		Bucket:     bucket,
		Prefix:     prefix,
		Region:     region,
		StartedAt:  time.Now(),
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
	}
}

// SetStartedAt overrides the start time (used on resume to keep the original
// run's start).
func (r *Report) SetStartedAt(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !t.IsZero() {
		r.StartedAt = t
	}
}

// AddRecord folds one ledger record into the aggregate.
func (r *Report) AddRecord(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case rec.Error != "":
		r.ErrorObjects++
	case rec.Skipped:
		r.SkippedObjects++
	default:
		r.ScannedObjects++
	}
	for _, f := range rec.Findings {
		r.TotalFindings++
		r.BySeverity[f.Severity]++
		r.ByCategory[f.Category]++
	}
}

// Finish marks the run complete and stamps the finish time.
func (r *Report) Finish(complete bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.FinishedAt = time.Now()
	r.Complete = complete
}

// WriteJSON writes the aggregate summary to path.
func (r *Report) WriteJSON(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Summary renders the terminal summary block.
func (r *Report) Summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "Scan summary for s3://%s/%s (%s)\n", r.Bucket, r.Prefix, r.Region)
	status := "COMPLETE"
	if !r.Complete {
		status = "INCOMPLETE (resumable)"
	}
	fmt.Fprintf(&b, "  status:   %s\n", status)
	fmt.Fprintf(&b, "  scanned:  %d   skipped: %d   errors: %d\n", r.ScannedObjects, r.SkippedObjects, r.ErrorObjects)
	fmt.Fprintf(&b, "  findings: %d\n", r.TotalFindings)

	if r.TotalFindings > 0 {
		b.WriteString("  by severity: ")
		b.WriteString(joinCounts(r.BySeverity, []string{"critical", "high", "medium", "low"}))
		b.WriteString("\n  by category: ")
		b.WriteString(joinCountsSorted(r.ByCategory))
		b.WriteString("\n")
	}
	if !r.FinishedAt.IsZero() {
		fmt.Fprintf(&b, "  elapsed: %s\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	}
	return b.String()
}

func joinCounts(m map[string]int, order []string) string {
	var parts []string
	for _, k := range order {
		if v, ok := m[k]; ok && v > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func joinCountsSorted(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
