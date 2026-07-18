package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	verification "pii_verification"
)

// Engine holds the compiled pattern set used to scan content.
type Engine struct {
	patterns []*Pattern
}

// Options controls which patterns are loaded.
type Options struct {
	// Locations, when non-empty, restricts patterns to these namespaces
	// (e.g. "comm", "kr", "us"). Empty means all.
	Locations []string
	// Categories, when non-empty, restricts patterns to these categories
	// (e.g. "credit_card", "email"). Empty means all.
	Categories []string
}

// Load walks a pii-pattern-engine regex directory (e.g. ".../regex"), parses
// every *.yml file, compiles the Go regex variant of each pattern, and resolves
// its verification function from the engine registry.
func Load(regexDir string, opts Options) (*Engine, error) {
	info, err := os.Stat(regexDir)
	if err != nil {
		return nil, fmt.Errorf("pattern directory %q: %w", regexDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pattern path %q is not a directory", regexDir)
	}

	locFilter := toSet(opts.Locations)
	catFilter := toSet(opts.Categories)

	e := &Engine{}
	var loadErrs []string

	walkErr := filepath.WalkDir(regexDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".yml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var file yamlFile
		if err := yaml.Unmarshal(raw, &file); err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		for _, yp := range file.Patterns {
			p, err := compile(yp)
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("%s [%s]: %v", path, yp.ID, err))
				continue
			}
			if len(locFilter) > 0 && !locFilter[p.Location] {
				continue
			}
			if len(catFilter) > 0 && !catFilter[p.Category] {
				continue
			}
			e.patterns = append(e.patterns, p)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(e.patterns) == 0 {
		if len(loadErrs) > 0 {
			return nil, fmt.Errorf("no patterns loaded; errors:\n  %s", strings.Join(loadErrs, "\n  "))
		}
		return nil, fmt.Errorf("no patterns matched the requested locations/categories under %q", regexDir)
	}
	// Higher priority and more severe patterns first so overlapping matches are
	// reported deterministically.
	sort.SliceStable(e.patterns, func(i, j int) bool {
		return severityRank(e.patterns[i].Severity) > severityRank(e.patterns[j].Severity)
	})
	return e, nil
}

func compile(yp yamlPattern) (*Pattern, error) {
	expr := yp.Langs["go"]
	if expr == "" {
		expr = yp.Pattern
	}
	if expr == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	re, err := regexpCompile(expr)
	if err != nil {
		return nil, fmt.Errorf("regex %q: %w", expr, err)
	}
	p := &Pattern{
		ID:           yp.ID,
		Location:     yp.Location,
		Category:     yp.Category,
		Description:  yp.Description,
		Severity:     strings.ToLower(yp.Policy.Severity),
		Mask:         yp.Mask,
		Verification: yp.Verification,
		re:           re,
	}
	if yp.Verification != "" {
		if fn, ok := verification.GetVerificationFunction(yp.Verification); ok {
			p.verify = fn
			p.verifyOK = true
		}
		// If the named function is not registered we keep the pattern but treat
		// it as regex-only; ReportUnresolved surfaces these for visibility.
	}
	return p, nil
}

// PatternCount returns the number of loaded patterns.
func (e *Engine) PatternCount() int { return len(e.patterns) }

// UnresolvedVerifications lists patterns whose verification function name could
// not be found in the engine registry (they run as regex-only).
func (e *Engine) UnresolvedVerifications() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range e.patterns {
		if p.Verification != "" && !p.verifyOK {
			if _, dup := seen[p.Verification]; !dup {
				seen[p.Verification] = struct{}{}
				out = append(out, p.Verification)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Scan finds all PII matches in content. A pattern that declares a verification
// function acts as a gate: matches that fail the checksum/validator are dropped
// (that is the engine's mechanism for suppressing false positives). Regex-only
// patterns report every match at their declared severity.
func (e *Engine) Scan(content []byte) []Finding {
	var findings []Finding
	// Precompute line-start offsets so we can map byte offsets to line numbers.
	lineStarts := lineIndex(content)
	text := bytesToString(content)

	for _, p := range e.patterns {
		locs := p.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			match := text[loc[0]:loc[1]]
			verified := false
			if p.verifyOK {
				if !p.verify(match) {
					continue // failed checksum -> almost certainly not real PII
				}
				verified = true
			}
			findings = append(findings, Finding{
				Source:      SourceRegex,
				PatternID:   p.ID,
				Category:    p.Category,
				Location:    p.Location,
				Description: p.Description,
				Severity:    p.Severity,
				Confidence:  score(p.Severity, verified, p.verifyOK),
				Verified:    verified,
				Masked:      maskValue(match, p.Mask),
				Line:        lineOf(lineStarts, loc[0]),
				ByteOffset:  loc[0],
				EndOffset:   loc[1],
			})
		}
	}
	return findings
}

// score produces a 0-100 confidence value. A severity base is boosted when a
// checksum/validator confirmed the match; regex-only matches keep the base.
func score(severity string, verified, hasVerifier bool) int {
	base := map[string]int{"critical": 70, "high": 60, "medium": 50, "low": 40}[severity]
	if base == 0 {
		base = 50
	}
	if hasVerifier && verified {
		base += 25
	}
	if base > 100 {
		base = 100
	}
	return base
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// maskValue renders a redacted representation of a matched value. If the pattern
// supplies a mask template of the same visible length it is used; otherwise the
// value is reduced to a length-preserving asterisk string that keeps only the
// last two characters for triage.
func maskValue(value, mask string) string {
	v := strings.TrimSpace(value)
	if mask != "" {
		return mask
	}
	if len(v) <= 2 {
		return strings.Repeat("*", len(v))
	}
	return strings.Repeat("*", len(v)-2) + v[len(v)-2:]
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" {
			m[it] = true
		}
	}
	return m
}

// lineIndex returns the byte offset at which each line begins.
func lineIndex(content []byte) []int {
	starts := []int{0}
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineOf(starts []int, offset int) int {
	// binary search for the last start <= offset
	lo, hi := 0, len(starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if starts[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

// bytesToString converts without copying for read-only regex use.
func bytesToString(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
