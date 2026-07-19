// Package engine adapts the zafrem/pii-pattern-engine (regex YAML rules plus Go
// checksum verification functions) into a streaming text matcher that produces
// scored, masked PII findings.
package engine

import "regexp"

// yamlFile mirrors the on-disk structure of a pattern YAML file such as
// pii-pattern-engine/regex/pii/common/credit-cards.yml.
type yamlFile struct {
	Namespace   string        `yaml:"namespace"`
	Description string        `yaml:"description"`
	Patterns    []yamlPattern `yaml:"patterns"`
}

type yamlPattern struct {
	ID           string            `yaml:"id"`
	Location     string            `yaml:"location"`
	Category     string            `yaml:"category"`
	Description  string            `yaml:"description"`
	Pattern      string            `yaml:"pattern"`
	Verification string            `yaml:"verification"`
	Mask         string            `yaml:"mask"`
	MatchType    string            `yaml:"match_type"`
	Priority     int               `yaml:"priority"`
	Policy       yamlPolicy        `yaml:"policy"`
	Langs        map[string]string `yaml:"langs"`
}

type yamlPolicy struct {
	StoreRaw      bool   `yaml:"store_raw"`
	ActionOnMatch string `yaml:"action_on_match"`
	Severity      string `yaml:"severity"`
}

// Pattern is a compiled, ready-to-run detection rule.
type Pattern struct {
	ID           string
	Location     string // region/namespace, e.g. "comm", "kr", "us"
	Category     string // e.g. "credit_card"
	Description  string
	Severity     string // critical|high|medium|low
	Mask         string
	Verification string // name of the checksum/validator function, may be empty

	re       *regexp.Regexp
	verify   func(string) bool // resolved from the engine registry, may be nil
	verifyOK bool              // whether a verification function was found
}

// Finding is a single PII match discovered in a piece of content.
type Finding struct {
	Source      string `json:"source"`     // "regex" (pattern engine) or "ner" (privyscope)
	PatternID   string `json:"pattern_id"` // regex rule id, or NER entity label for source=ner
	Category    string `json:"category"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  int    `json:"confidence"` // 0-100
	Verified    bool   `json:"verified"`   // a checksum/validator confirmed the match
	Masked      string `json:"masked"`     // redacted representation of the match
	Line        int    `json:"line"`       // 1-based line number within the object
	ByteOffset  int    `json:"byte_offset"`
	EndOffset   int    `json:"end_offset"` // exclusive byte offset of the match end
}

// Source values.
const (
	SourceRegex = "regex"
	SourceNER   = "ner"
)
