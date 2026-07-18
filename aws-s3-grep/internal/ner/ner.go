// Package ner is an HTTP client for the privyscope NER sidecar. It turns the
// sidecar's character-offset entity spans into engine.Findings whose byte
// offsets align with the regex engine's findings, so the two can be merged.
package ner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zafrem/pii-utils/aws-s3-grep/internal/engine"
)

// nerConfidence is a fixed confidence for NER findings: the privyscope span
// schema carries no per-entity score, so we cannot derive one. It sits below a
// checksum-verified regex hit but above an unverified regex match.
const nerConfidence = 75

// Client talks to a privyscope NER sidecar.
type Client struct {
	endpoint string
	http     *http.Client
}

// New returns a client for the sidecar base URL (e.g. http://127.0.0.1:8080).
func New(endpoint string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		http:     &http.Client{Timeout: timeout},
	}
}

type healthResp struct {
	Status    string   `json:"status"`
	HasNER    bool     `json:"has_ner"`
	Languages []string `json:"languages"`
}

// Ping verifies the sidecar is reachable and healthy, returning its languages.
func (c *Client) Ping(ctx context.Context) (langs []string, hasNER bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("NER sidecar unreachable at %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("NER sidecar health returned %s", resp.Status)
	}
	var h healthResp
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, false, fmt.Errorf("decode health: %w", err)
	}
	return h.Languages, h.HasNER, nil
}

type span struct {
	Label string `json:"label"`
	Start int    `json:"start"` // inclusive char offset
	End   int    `json:"end"`   // exclusive char offset
	Text  string `json:"text"`
}

type analyzeResp struct {
	Schema  int `json:"schema"`
	Results []struct {
		Spans []span `json:"spans"`
	} `json:"results"`
	Error string `json:"error"`
}

// Analyze sends one text to the sidecar and maps the returned spans to findings.
func (c *Client) Analyze(ctx context.Context, text string) ([]engine.Finding, error) {
	body, err := json.Marshal(map[string]any{"texts": []string{text}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NER analyze: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NER analyze returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var ar analyzeResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("decode analyze response: %w", err)
	}
	if ar.Error != "" {
		return nil, fmt.Errorf("NER sidecar error: %s", ar.Error)
	}
	if len(ar.Results) == 0 {
		return nil, nil
	}
	return spansToFindings(text, ar.Results[0].Spans), nil
}

// spansToFindings converts character-offset spans into byte-offset findings.
func spansToFindings(text string, spans []span) []engine.Finding {
	if len(spans) == 0 {
		return nil
	}
	byteAt := runeByteOffsets(text)
	nRunes := len(byteAt) - 1

	out := make([]engine.Finding, 0, len(spans))
	for _, s := range spans {
		if s.Start < 0 || s.End < s.Start || s.End > nRunes {
			continue // defensive: ignore malformed offsets
		}
		startByte := byteAt[s.Start]
		endByte := byteAt[s.End]
		label := strings.ToUpper(s.Label)
		out = append(out, engine.Finding{
			Source:      engine.SourceNER,
			PatternID:   label,
			Category:    strings.ToLower(s.Label),
			Location:    "ner",
			Description: "NER entity: " + label,
			Severity:    severityFor(label),
			Confidence:  nerConfidence,
			Verified:    false,
			Masked:      "<" + label + ">",
			Line:        1 + strings.Count(text[:startByte], "\n"),
			ByteOffset:  startByte,
			EndOffset:   endByte,
		})
	}
	return out
}

// runeByteOffsets returns a table mapping rune index -> byte index, with a final
// entry equal to len(text). privyscope offsets are Python string indices (one
// per Unicode code point), which correspond to Go rune boundaries.
func runeByteOffsets(text string) []int {
	offs := make([]int, 0, len(text)+1)
	for i := range text { // range yields the byte index at each rune start
		offs = append(offs, i)
	}
	offs = append(offs, len(text))
	return offs
}

// severityFor assigns a default severity to a privyscope entity label. privyscope
// spans carry no severity, so this is a fixed policy mapping.
func severityFor(label string) string {
	switch label {
	case "ID_NUM", "SECRET", "BANK":
		return "critical"
	case "PER", "PHONE", "EMAIL":
		return "high"
	case "LOC":
		return "medium"
	default: // DATE and anything new
		return "low"
	}
}
