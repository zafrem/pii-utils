package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/engine"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/report"
)

func rec(key string, findings int) report.Record {
	r := report.Record{Key: key, Size: 10, BytesScanned: 10}
	for i := 0; i < findings; i++ {
		r.Findings = append(r.Findings, engine.Finding{
			PatternID: "p", Category: "credit_card", Severity: "critical", Confidence: 95,
		})
	}
	return r
}

func meta() Meta {
	return Meta{Bucket: "b", Prefix: "p/", Region: "us-east-1", Categories: []string{"credit_card"}}
}

func TestResumeRebuildsStateAndAggregate(t *testing.T) {
	dir := t.TempDir()

	// First run: record 3 objects, one with 2 findings, then close (simulating
	// an interrupt).
	s1, resumed, err := Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	if resumed {
		t.Fatal("fresh dir should not be a resume")
	}
	for _, r := range []report.Record{rec("a", 0), rec("b", 2), rec("c", 0)} {
		if err := s1.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Second run: reopen and confirm resume state.
	s2, resumed, err := Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed {
		t.Fatal("expected resume=true after prior progress")
	}
	if !s2.Done("a") || !s2.Done("b") || !s2.Done("c") {
		t.Fatal("completed keys not reconstructed from ledger")
	}
	if s2.Done("d") {
		t.Fatal("unprocessed key reported done")
	}
	if got := s2.CompletedCount(); got != 3 {
		t.Fatalf("CompletedCount = %d, want 3", got)
	}
	rp := s2.Report()
	if rp.ScannedObjects != 3 {
		t.Errorf("ScannedObjects = %d, want 3", rp.ScannedObjects)
	}
	if rp.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2 (aggregate must survive resume)", rp.TotalFindings)
	}

	// Append one more and confirm the ledger keeps growing (append, not
	// truncate).
	if err := s2.Record(rec("d", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s2.WriteSummary(true, ""); err != nil {
		t.Fatal(err)
	}
	s2.Close()

	lines := countLines(t, filepath.Join(dir, resultsName))
	if lines != 4 {
		t.Fatalf("ledger has %d lines, want 4 (3 from run 1 + 1 from run 2)", lines)
	}
	if _, err := os.Stat(filepath.Join(dir, summaryName)); err != nil {
		t.Errorf("summary.json not written: %v", err)
	}
}

func TestReplayToleratesTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	s.Record(rec("a", 1))
	s.Close()

	// Simulate a crash mid-write: append a partial JSON line with no newline.
	f, err := os.OpenFile(filepath.Join(dir, resultsName), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"key":"b","siz`)
	f.Close()

	s2, resumed, err := Open(dir, meta(), false)
	if err != nil {
		t.Fatalf("Open must tolerate a truncated tail, got: %v", err)
	}
	if !resumed || !s2.Done("a") {
		t.Fatal("valid record before the truncated tail must survive")
	}
	if s2.Done("b") {
		t.Fatal("truncated record must not be treated as done")
	}
	s2.Close()
}

func TestFingerprintMismatchRefusesResume(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir, meta(), false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	other := meta()
	other.Categories = []string{"email"} // different selection => different fingerprint
	if _, _, err := Open(dir, other, false); err == nil {
		t.Fatal("expected an error resuming a session with a different fingerprint")
	}

	// --fresh should override and succeed, archiving the old ledger.
	s3, resumed, err := Open(dir, other, true)
	if err != nil {
		t.Fatalf("--fresh should start over cleanly: %v", err)
	}
	if resumed {
		t.Fatal("--fresh must not resume")
	}
	s3.Close()
}

func countLines(t *testing.T, path string) int {
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
