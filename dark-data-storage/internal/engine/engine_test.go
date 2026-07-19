package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// patternsDir locates the submodule regex directory relative to this package,
// skipping the test if the submodule is not checked out.
func patternsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "pii-pattern-engine", "regex")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("pattern submodule not available at %s: %v", dir, err)
	}
	return dir
}

func TestLoadPatterns(t *testing.T) {
	eng, err := Load(patternsDir(t), Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if eng.PatternCount() == 0 {
		t.Fatal("expected patterns to load")
	}
	t.Logf("loaded %d patterns; unresolved verifications: %v", eng.PatternCount(), eng.UnresolvedVerifications())
}

func TestScanDetectsCreditCard(t *testing.T) {
	eng, err := Load(patternsDir(t), Options{Categories: []string{"credit_card"}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	content := []byte("customer paid with 4111111111111111 on file\n")
	findings := eng.Scan(content)
	if len(findings) == 0 {
		t.Fatal("expected a credit card finding")
	}
	f := findings[0]
	if f.Category != "credit_card" {
		t.Errorf("category = %q, want credit_card", f.Category)
	}
	if f.Line != 1 {
		t.Errorf("line = %d, want 1", f.Line)
	}
	if f.Masked == "4111111111111111" {
		t.Error("raw value must not appear in masked output")
	}
	t.Logf("finding: %+v", f)
}

// TestVerificationGate confirms that a value failing a checksum validator is
// dropped, while a valid one is kept. Uses the Korean business-registration rule
// (verification: kr_business_registration_valid); 123-45-67891 is the valid
// example, 123-45-67890 the invalid one from the engine's own YAML.
func TestVerificationGate(t *testing.T) {
	eng, err := Load(patternsDir(t), Options{Locations: []string{"kr"}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	valid := eng.Scan([]byte("사업자등록번호 123-45-67891"))
	if !hasCategory(valid, "other") && len(valid) == 0 {
		t.Fatal("expected the valid business-registration number to be detected")
	}
	invalid := eng.Scan([]byte("number 123-45-67890"))
	for _, f := range invalid {
		if f.PatternID == "business_registration_01" {
			t.Errorf("invalid check digit should have been dropped, got %+v", f)
		}
	}
}

func hasCategory(fs []Finding, cat string) bool {
	for _, f := range fs {
		if f.Category == cat {
			return true
		}
	}
	return false
}
