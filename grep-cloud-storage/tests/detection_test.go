package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/engine"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/ner"
)

// TestEngineLoadsAllPatterns confirms the full rule set loads and, now that the
// engine's Go validators are complete, that no rule falls back to regex-only.
func TestEngineLoadsAllPatterns(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if eng.PatternCount() == 0 {
		t.Fatal("no patterns loaded")
	}
	if un := eng.UnresolvedVerifications(); len(un) != 0 {
		t.Errorf("expected every verification to resolve, unresolved: %v", un)
	}
}

// TestRegexScanAndVerificationGate checks a positive detection plus the checksum
// gate that suppresses false positives.
func TestRegexScanAndVerificationGate(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	f := eng.Scan([]byte("card 4111111111111111 here"))
	if !hasCategory(f, "credit_card") {
		t.Fatal("expected a credit_card finding")
	}
	for _, x := range f {
		if x.Source != engine.SourceRegex {
			t.Errorf("regex scan produced source %q", x.Source)
		}
		if x.Masked == "4111111111111111" {
			t.Error("raw value leaked into masked output")
		}
	}

	// An invalid Korean business-registration number must be dropped by its
	// verification function (valid example: 123-45-67891).
	for _, x := range eng.Scan([]byte("no 123-45-67890 here")) {
		if x.PatternID == "business_registration_01" {
			t.Errorf("invalid checksum should have been gated, got %+v", x)
		}
	}
}

// TestScannerPipelineMergesRegexAndNER reproduces the per-object flow in
// scanner.scanOne: regex scan, then NER via the sidecar client, then Merge. It
// asserts NER entities are additive while an NER span overlapping a regex hit is
// dropped in favour of the richer regex finding.
func TestScannerPipelineMergesRegexAndNER(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Runes: "pay " (0-3) | card (4-19) | " " (20) | "zzzzzzzz" (21-28).
	// The filler is deliberately non-PII so the additive NER entity below does
	// not collide with any regex rule (e.g. the name validators).
	content := []byte("pay 4111111111111111 zzzzzzzz")

	// Fake sidecar: one PER entity over the filler (additive) and one span over
	// the credit card (overlaps a regex hit, so Merge must drop it).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "has_ner": true, "languages": []string{"ko"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"schema": 1,
			"results": []any{map[string]any{"spans": []any{
				map[string]any{"label": "PER", "start": 21, "end": 29, "text": "zzzzzzzz"},
				map[string]any{"label": "ID_NUM", "start": 4, "end": 20, "text": "4111111111111111"},
			}}},
		})
	}))
	defer srv.Close()

	regexF := eng.Scan(content)
	// Precondition: regex must not itself flag the filler, or the additive
	// assertion below would be testing the wrong thing.
	for _, f := range regexF {
		if f.ByteOffset < 29 && f.EndOffset > 21 {
			t.Fatalf("test filler unexpectedly matched a regex rule: %+v", f)
		}
	}
	nerF, err := ner.New(srv.URL, 0).Analyze(context.Background(), string(content))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	merged := engine.Merge(regexF, nerF)

	// The additive PER entity survives.
	if !hasSource(merged, engine.SourceNER, "per") {
		t.Error("expected the non-overlapping NER PER entity to be kept")
	}
	// The NER span overlapping the credit card (bytes [4,20)) is dropped.
	for _, f := range merged {
		if f.Source == engine.SourceNER && f.ByteOffset < 20 && f.EndOffset > 4 {
			t.Errorf("NER span overlapping the regex credit card should have been dropped: %+v", f)
		}
	}
	// The regex credit card is still present exactly once.
	if n := countCategory(merged, "credit_card"); n != 1 {
		t.Errorf("credit_card findings = %d, want 1", n)
	}
}

func hasCategory(fs []engine.Finding, cat string) bool {
	for _, f := range fs {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func hasSource(fs []engine.Finding, source, cat string) bool {
	for _, f := range fs {
		if f.Source == source && f.Category == cat {
			return true
		}
	}
	return false
}

func countCategory(fs []engine.Finding, cat string) int {
	n := 0
	for _, f := range fs {
		if f.Category == cat {
			n++
		}
	}
	return n
}
