package ner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zafrem/pii-utils/aws-s3-grep/internal/engine"
)

// TestAnalyzeCharToByteOffsets checks that character offsets from the sidecar
// are converted to byte offsets that match Go's view of the same multibyte
// (Korean) text, and that line numbers are computed correctly.
func TestAnalyzeCharToByteOffsets(t *testing.T) {
	// runes: 홍(0)길(1)동(2) (3) t(4)e(5)s(6)t(7) (8) 0(9)... phone runs to rune 22.
	// Each Korean syllable is 3 bytes in UTF-8; the rest are ASCII.
	text := "홍길동 test 010-1234-5678"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "has_ner": true, "languages": []string{"ko"}})
			return
		}
		// /analyze — return spans in CHARACTER offsets, as privyscope does.
		json.NewEncoder(w).Encode(map[string]any{
			"schema": 1,
			"results": []any{map[string]any{"spans": []any{
				map[string]any{"label": "PER", "start": 0, "end": 3, "text": "홍길동"},
				map[string]any{"label": "PHONE", "start": 9, "end": 22, "text": "010-1234-5678"},
			}}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 0)
	if _, hasNER, err := c.Ping(context.Background()); err != nil || !hasNER {
		t.Fatalf("Ping: hasNER=%v err=%v", hasNER, err)
	}

	findings, err := c.Analyze(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	per := findings[0]
	if per.Source != engine.SourceNER || per.PatternID != "PER" {
		t.Errorf("PER: source=%q id=%q", per.Source, per.PatternID)
	}
	// "홍길동" = 3 syllables x 3 bytes = bytes [0,9).
	if per.ByteOffset != 0 || per.EndOffset != 9 {
		t.Errorf("PER byte offsets = [%d,%d), want [0,9)", per.ByteOffset, per.EndOffset)
	}
	if per.Severity != "high" {
		t.Errorf("PER severity = %q, want high", per.Severity)
	}

	phone := findings[1]
	// Byte offset of rune 9: 홍길동(9) + space(1) + "test"(4) + space(1) = 15.
	if phone.ByteOffset != 15 || phone.EndOffset != 28 {
		t.Errorf("PHONE byte offsets = [%d,%d), want [15,28)", phone.ByteOffset, phone.EndOffset)
	}
	if phone.Masked != "<PHONE>" {
		t.Errorf("PHONE masked = %q, want <PHONE>", phone.Masked)
	}
	if phone.Line != 1 {
		t.Errorf("PHONE line = %d, want 1", phone.Line)
	}

	// Verify the byte offsets actually index the intended substrings.
	if text[per.ByteOffset:per.EndOffset] != "홍길동" {
		t.Errorf("PER slice = %q", text[per.ByteOffset:per.EndOffset])
	}
	if text[phone.ByteOffset:phone.EndOffset] != "010-1234-5678" {
		t.Errorf("PHONE slice = %q", text[phone.ByteOffset:phone.EndOffset])
	}
}

func TestAnalyzeServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "boom"})
	}))
	defer srv.Close()

	if _, err := New(srv.URL, 0).Analyze(context.Background(), "x"); err == nil {
		t.Fatal("expected an error from a 400 response")
	}
}
