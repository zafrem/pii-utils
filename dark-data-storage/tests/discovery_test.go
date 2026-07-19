package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/discovery"
)

func TestAssessGovernedBucketIsNotFlagged(t *testing.T) {
	a := discovery.Assess(discovery.BucketFacts{
		Name:         "prod-app-data",
		Region:       "us-east-1",
		Encrypted:    true,
		EncryptKnown: true,
		Tagged:       true,
		TagKnown:     true,
	})
	if a.Flagged {
		t.Fatal("a private, encrypted, tagged bucket must not be flagged")
	}
	if a.Tier != discovery.TierLow {
		t.Errorf("governed bucket tier = %v, want low", a.Tier)
	}
	if a.Score != 0 {
		t.Errorf("governed bucket score = %d, want 0", a.Score)
	}
}

func TestAssessPublicBucketIsCritical(t *testing.T) {
	a := discovery.Assess(discovery.BucketFacts{
		Name:         "public-assets",
		Public:       true,
		PublicVia:    "policy",
		Encrypted:    true,
		EncryptKnown: true,
		Tagged:       true,
		TagKnown:     true,
	})
	if !a.Flagged {
		t.Fatal("a public bucket must be flagged")
	}
	if a.Tier != discovery.TierCritical {
		t.Errorf("public bucket tier = %v, want critical", a.Tier)
	}
	if !strings.Contains(strings.Join(a.Reasons, " "), "publicly accessible") {
		t.Errorf("reasons should mention public access, got %v", a.Reasons)
	}
}

func TestAssessGovernanceGapsStack(t *testing.T) {
	// Unencrypted (+25) and untagged (+15) → 40 → high tier.
	a := discovery.Assess(discovery.BucketFacts{
		Name:         "forgotten-exports",
		EncryptKnown: true, // Encrypted false
		TagKnown:     true, // Tagged false
	})
	if !a.Flagged {
		t.Fatal("an unencrypted, untagged bucket must be flagged")
	}
	if a.Score != 40 {
		t.Errorf("score = %d, want 40 (25 unencrypted + 15 untagged)", a.Score)
	}
	if a.Tier != discovery.TierHigh {
		t.Errorf("tier = %v, want high", a.Tier)
	}
}

func TestAssessIncompleteAuditIsFlagged(t *testing.T) {
	// Unknown encryption/tagging (not *Known) plus an audit error: we cannot
	// confirm the bucket is safe, so it must be flagged and not scored as clean.
	a := discovery.Assess(discovery.BucketFacts{
		Name:   "denied-bucket",
		Errors: []string{"acl: AccessDenied"},
	})
	if !a.Flagged {
		t.Fatal("a bucket we could not fully audit must be flagged")
	}
	if !strings.Contains(strings.Join(a.Reasons, " "), "audit incomplete") {
		t.Errorf("reasons should note the incomplete audit, got %v", a.Reasons)
	}
}

func TestUnknownGovernanceIsNotPenalizedAsConfirmed(t *testing.T) {
	// EncryptKnown/TagKnown false means "unverified": scoring must NOT add the
	// unencrypted/untagged penalty for something it never confirmed absent.
	unverified := discovery.Assess(discovery.BucketFacts{Name: "a", EncryptKnown: false, TagKnown: false})
	if unverified.Score != 0 {
		t.Errorf("unverified governance scored %d, want 0 (no confirmed gaps)", unverified.Score)
	}
	// Confirmed-absent (Known=true, value=false) is the penalized case: +25 +15.
	confirmedAbsent := discovery.Assess(discovery.BucketFacts{Name: "b", EncryptKnown: true, TagKnown: true})
	if confirmedAbsent.Score != 40 {
		t.Errorf("confirmed-absent governance scored %d, want 40", confirmedAbsent.Score)
	}
}

func TestAssessAllOrdersMostDarkFirst(t *testing.T) {
	got := discovery.AssessAll([]discovery.BucketFacts{
		{Name: "governed", Encrypted: true, EncryptKnown: true, Tagged: true, TagKnown: true},
		{Name: "public", Public: true, PublicVia: "acl", Encrypted: true, EncryptKnown: true, Tagged: true, TagKnown: true},
		{Name: "untagged", TagKnown: true, Encrypted: true, EncryptKnown: true},
	})
	if len(got) != 3 {
		t.Fatalf("got %d assessments, want 3", len(got))
	}
	if got[0].Name != "public" {
		t.Errorf("most-dark bucket = %q, want public", got[0].Name)
	}
	if got[len(got)-1].Name != "governed" {
		t.Errorf("least-dark bucket = %q, want governed", got[len(got)-1].Name)
	}
}

func TestTierAtLeast(t *testing.T) {
	cases := map[string]discovery.Tier{
		"critical": discovery.TierCritical,
		"high":     discovery.TierHigh,
		"medium":   discovery.TierMedium,
		"low":      discovery.TierLow,
		"":         discovery.TierLow,
		"garbage":  discovery.TierLow,
	}
	for in, want := range cases {
		if got := discovery.TierAtLeast(in); got != want {
			t.Errorf("TierAtLeast(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSelect(t *testing.T) {
	assessments := discovery.AssessAll([]discovery.BucketFacts{
		{Name: "public", Public: true, PublicVia: "policy"},                                   // critical, flagged
		{Name: "untagged", TagKnown: true, Encrypted: true, EncryptKnown: true},               // low, flagged
		{Name: "governed", Encrypted: true, EncryptKnown: true, Tagged: true, TagKnown: true}, // low, not flagged
		{Name: "unenc-untagged", EncryptKnown: true, TagKnown: true},                          // high, flagged
	})

	names := func(sel discovery.Selection) []string {
		var out []string
		for _, a := range discovery.Select(assessments, sel) {
			out = append(out, a.Name)
		}
		return out
	}

	// Default: flagged only (governed excluded).
	if got := names(discovery.Selection{}); !equalSet(got, []string{"public", "untagged", "unenc-untagged"}) {
		t.Errorf("default selection = %v, want the three flagged buckets", got)
	}
	// All buckets includes the governed one.
	if got := names(discovery.Selection{All: true}); len(got) != 4 {
		t.Errorf("all-buckets selection = %v, want 4", got)
	}
	// MinTier high: only public (critical) and unenc-untagged (high).
	if got := names(discovery.Selection{MinTier: "high"}); !equalSet(got, []string{"public", "unenc-untagged"}) {
		t.Errorf("min-tier high selection = %v, want public + unenc-untagged", got)
	}
	// All buckets but min-tier critical: only public.
	if got := names(discovery.Selection{All: true, MinTier: "critical"}); !equalSet(got, []string{"public"}) {
		t.Errorf("all + min-tier critical = %v, want just public", got)
	}
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestWriteJSONRoundTrips(t *testing.T) {
	assessments := discovery.AssessAll([]discovery.BucketFacts{
		{Name: "public", Public: true, PublicVia: "policy"},
		{Name: "governed", Encrypted: true, EncryptKnown: true, Tagged: true, TagKnown: true},
	})
	path := filepath.Join(t.TempDir(), "discovery.json")
	if err := discovery.WriteJSON(path, assessments); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var doc struct {
		Buckets     int `json:"buckets"`
		Flagged     int `json:"flagged"`
		Public      int `json:"public"`
		Assessments []struct {
			Name    string `json:"Name"`
			Flagged bool   `json:"Flagged"`
		} `json:"assessments"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Buckets != 2 || doc.Public != 1 || doc.Flagged != 1 {
		t.Errorf("header counts = buckets %d, public %d, flagged %d; want 2/1/1", doc.Buckets, doc.Public, doc.Flagged)
	}
	if len(doc.Assessments) != 2 {
		t.Fatalf("got %d assessments in file, want 2", len(doc.Assessments))
	}
}
