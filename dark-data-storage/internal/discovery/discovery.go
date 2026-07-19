// Package discovery classifies cloud storage buckets by how "dark" they are —
// how exposed and how ungoverned. The AWS-facing audit lives in the awsx
// package; the scoring here is pure so it can be unit-tested without any cloud
// access and reused verbatim when GCS/Azure providers are added.
package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// BucketFacts is the raw, provider-neutral audit of one bucket, filled in by the
// storage provider (awsx for S3). Unknowns are represented by the *Known flags:
// when the audit could not read a property (e.g. AccessDenied), the property is
// left false and its cause recorded in Errors, and the corresponding *Known flag
// is false so scoring treats it as "unverified" rather than "confirmed absent".
type BucketFacts struct {
	Name         string
	Region       string
	CreatedAt    time.Time
	Objects      int64 // approximate object count from a bounded LIST (0 = unknown)
	ApproxCount  bool  // Objects is a lower bound (LIST was capped)
	Public       bool  // reachable by anonymous/any-AWS principals
	PublicVia    string
	Encrypted    bool
	EncryptKnown bool
	Tagged       bool
	TagKnown     bool
	Errors       []string // audit steps that could not be completed
}

// Tier ranks a bucket's dark-data risk.
type Tier int

const (
	TierLow Tier = iota
	TierMedium
	TierHigh
	TierCritical
)

func (t Tier) String() string {
	switch t {
	case TierCritical:
		return "critical"
	case TierHigh:
		return "high"
	case TierMedium:
		return "medium"
	default:
		return "low"
	}
}

// Scoring weights. Public exposure dominates; missing governance signals
// (encryption, tags) stack on top.
const (
	scorePublic      = 60
	scoreUnencrypted = 25
	scoreUntagged    = 15
	scoreUnverified  = 10 // audit was incomplete — treat unknowns as suspicious
)

// Assessment is a scored, human-readable verdict for one bucket.
type Assessment struct {
	BucketFacts
	Score   int
	Tier    Tier
	Reasons []string
	// Flagged is true when the bucket has any exposure or governance gap and so
	// is scanned by default. Fully-governed buckets (private, encrypted, tagged,
	// fully audited) are not flagged.
	Flagged bool
}

// Assess scores a single bucket.
func Assess(f BucketFacts) Assessment {
	a := Assessment{BucketFacts: f}

	if f.Public {
		a.Score += scorePublic
		via := f.PublicVia
		if via == "" {
			via = "public access"
		}
		a.Reasons = append(a.Reasons, "publicly accessible ("+via+")")
	}
	if f.EncryptKnown && !f.Encrypted {
		a.Score += scoreUnencrypted
		a.Reasons = append(a.Reasons, "no default encryption")
	}
	if f.TagKnown && !f.Tagged {
		a.Score += scoreUntagged
		a.Reasons = append(a.Reasons, "untagged / ungoverned")
	}
	if len(f.Errors) > 0 {
		a.Score += scoreUnverified
		a.Reasons = append(a.Reasons, "audit incomplete: "+strings.Join(f.Errors, "; "))
	}

	switch {
	case a.Score >= 60:
		a.Tier = TierCritical
	case a.Score >= 40:
		a.Tier = TierHigh
	case a.Score >= 20:
		a.Tier = TierMedium
	default:
		a.Tier = TierLow
	}

	// Flag anything with an exposure/governance gap, or that we could not fully
	// verify — that is exactly the shadow storage worth scanning.
	a.Flagged = f.Public ||
		(f.EncryptKnown && !f.Encrypted) ||
		(f.TagKnown && !f.Tagged) ||
		len(f.Errors) > 0
	if !a.Flagged {
		a.Reasons = append(a.Reasons, "governed: private, encrypted, and tagged")
	}
	return a
}

// AssessAll scores every bucket and returns them ordered most-dark first
// (highest score, then name for a stable order).
func AssessAll(facts []BucketFacts) []Assessment {
	out := make([]Assessment, 0, len(facts))
	for _, f := range facts {
		out = append(out, Assess(f))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Selection controls which assessed buckets are chosen for scanning.
type Selection struct {
	All     bool   // scan every bucket, not just the flagged (ungoverned) ones
	MinTier string // only include buckets at/above this tier (empty = no floor)
}

// Select picks which assessed buckets to scan: flagged ones by default,
// everything when All is set, filtered by a MinTier floor when given. Input
// order is preserved.
func Select(assessments []Assessment, sel Selection) []Assessment {
	min := TierAtLeast(sel.MinTier)
	var out []Assessment
	for _, a := range assessments {
		if !sel.All && !a.Flagged {
			continue
		}
		if sel.MinTier != "" && a.Tier < min {
			continue
		}
		out = append(out, a)
	}
	return out
}

// TierAtLeast parses a minimum-tier filter string ("low"/"medium"/"high"/
// "critical"). Unknown values fall back to TierLow.
func TierAtLeast(s string) Tier {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return TierCritical
	case "high":
		return TierHigh
	case "medium":
		return TierMedium
	default:
		return TierLow
	}
}

// WriteJSON persists the assessments (newest audit wins) as an indented JSON
// document with a small header, for machine consumption and record-keeping.
func WriteJSON(path string, assessments []Assessment) error {
	var flagged, public int
	for _, a := range assessments {
		if a.Flagged {
			flagged++
		}
		if a.Public {
			public++
		}
	}
	doc := struct {
		GeneratedAt time.Time    `json:"generated_at"`
		Buckets     int          `json:"buckets"`
		Flagged     int          `json:"flagged"`
		Public      int          `json:"public"`
		Assessments []Assessment `json:"assessments"`
	}{time.Now().UTC(), len(assessments), flagged, public, assessments}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Summary renders the discovery result as an aligned, human-readable table.
func Summary(assessments []Assessment) string {
	var b strings.Builder
	var flagged, public int
	for _, a := range assessments {
		if a.Flagged {
			flagged++
		}
		if a.Public {
			public++
		}
	}
	fmt.Fprintf(&b, "Discovered %d bucket(s): %d flagged as dark/ungoverned, %d publicly accessible.\n",
		len(assessments), flagged, public)
	for _, a := range assessments {
		mark := " "
		if a.Flagged {
			mark = "!"
		}
		region := a.Region
		if region == "" {
			region = "?"
		}
		fmt.Fprintf(&b, " %s [%-8s] %-40s %-14s  %s\n",
			mark, a.Tier, truncate(a.Name, 40), region, strings.Join(a.Reasons, "; "))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
