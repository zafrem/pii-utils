package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zafrem/pii-utils/aws-s3-grep/internal/engine"
	"github.com/zafrem/pii-utils/aws-s3-grep/internal/report"
	"github.com/zafrem/pii-utils/aws-s3-grep/internal/session"
)

func meta() session.Meta {
	return session.Meta{Bucket: "b", Prefix: "logs/", Region: "us-east-1", Categories: []string{"credit_card"}}
}

func record(key string, findings int) report.Record {
	r := report.Record{Key: key, Size: 20, BytesScanned: 20}
	for i := 0; i < findings; i++ {
		r.Findings = append(r.Findings, engine.Finding{
			Source: engine.SourceRegex, Category: "credit_card", Severity: "critical", Confidence: 95,
		})
	}
	return r
}

// TestSessionContinuousLedgerAndResume covers the two behaviours the session was
// built for: results are appended durably as they occur, and a re-open resumes —
// rebuilding the completed-key set and the aggregate from the ledger.
func TestSessionContinuousLedgerAndResume(t *testing.T) {
	dir := t.TempDir()

	s1, resumed, err := session.Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	if resumed {
		t.Fatal("a fresh directory should not resume")
	}
	for _, r := range []report.Record{record("a", 0), record("b", 2), record("c", 0)} {
		if err := s1.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	// The ledger must be on disk mid-run (continuous), before any summary write.
	if got := countFileLines(t, filepath.Join(dir, "results.jsonl")); got != 3 {
		t.Fatalf("ledger has %d lines mid-run, want 3", got)
	}
	s1.Close()

	// Re-open: resume.
	s2, resumed, err := session.Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed {
		t.Fatal("expected resume after prior progress")
	}
	if !s2.Done("a") || !s2.Done("b") || !s2.Done("c") || s2.Done("z") {
		t.Fatal("completed-key set not rebuilt from ledger")
	}
	if got := s2.Report().TotalFindings; got != 2 {
		t.Errorf("aggregate TotalFindings = %d, want 2 across resume", got)
	}
	if err := s2.Record(record("d", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s2.WriteSummary(true, ""); err != nil {
		t.Fatal(err)
	}
	s2.Close()

	if got := countFileLines(t, filepath.Join(dir, "results.jsonl")); got != 4 {
		t.Fatalf("ledger has %d lines after resume, want 4 (appended, not truncated)", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); err != nil {
		t.Errorf("summary.json missing: %v", err)
	}
}

func TestSessionRefusesFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	s, _, err := session.Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	other := meta()
	other.Categories = []string{"email"} // different selection => different fingerprint
	if _, _, err := session.Open(dir, other, false); err == nil {
		t.Fatal("expected refusal to resume a mismatched target/pattern set")
	}
	// --fresh overrides.
	s3, resumed, err := session.Open(dir, other, true)
	if err != nil {
		t.Fatalf("--fresh should start over: %v", err)
	}
	if resumed {
		t.Fatal("--fresh must not resume")
	}
	s3.Close()
}

func countFileLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	return n
}
