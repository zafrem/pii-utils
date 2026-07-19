package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/engine"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/extract"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/provider"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/scanner"
)

// makePDF builds a minimal, well-formed one-page PDF whose only content is the
// given text, computing the xref byte offsets so the parser accepts it.
func makePDF(text string) []byte {
	var buf bytes.Buffer
	offsets := make([]int, 6)
	obj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	buf.WriteString("%PDF-1.4\n")
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
	stream := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET"
	obj(4, "<< /Length "+strconv.Itoa(len(stream))+" >>\nstream\n"+stream+"\nendstream")
	obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefPos := buf.Len()
	buf.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefPos)
	return buf.Bytes()
}

// makeOOXML builds a ZIP (the office container) with the given part/content
// pairs, so tests can synthesize a .docx/.xlsx/.pptx without external tooling.
func makeOOXML(parts map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range parts {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func TestExtractPDF(t *testing.T) {
	text, kind, ok := extract.Text(makePDF("SSN 123-45-6789 card 4111111111111111"))
	if !ok || kind != "pdf" {
		t.Fatalf("extract PDF: ok=%v kind=%q", ok, kind)
	}
	if !strings.Contains(text, "4111111111111111") {
		t.Errorf("extracted PDF text missing content: %q", text)
	}
}

func TestExtractOfficeFormats(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		parts map[string]string
	}{
		{
			name: "docx",
			kind: "docx",
			parts: map[string]string{
				"[Content_Types].xml": "<Types/>",
				"word/document.xml":   `<w:document><w:body><w:p><w:r><w:t>card 4111111111111111</w:t></w:r></w:p></w:body></w:document>`,
			},
		},
		{
			name: "xlsx",
			kind: "xlsx",
			parts: map[string]string{
				"xl/sharedStrings.xml": `<sst><si><t>card 4111111111111111</t></si></sst>`,
			},
		},
		{
			name: "pptx",
			kind: "pptx",
			parts: map[string]string{
				"ppt/slides/slide1.xml": `<p:sld><a:t>card 4111111111111111</a:t></p:sld>`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, kind, ok := extract.Text(makeOOXML(tc.parts))
			if !ok || kind != tc.kind {
				t.Fatalf("extract %s: ok=%v kind=%q", tc.name, ok, kind)
			}
			if !strings.Contains(text, "4111111111111111") {
				t.Errorf("extracted %s text missing content: %q", tc.name, text)
			}
		})
	}
}

func TestExtractRejectsNonDocuments(t *testing.T) {
	// Plain text and a NUL-laden binary blob are not documents: extraction must
	// decline so the scanner falls back to its normal (text / binary) handling.
	if _, _, ok := extract.Text([]byte("just some plain text 4111111111111111")); ok {
		t.Error("plain text must not be treated as a document")
	}
	if _, _, ok := extract.Text([]byte{0x00, 0x01, 0x02, 0x03, 'P', 'K'}); ok {
		t.Error("random binary must not be treated as a document")
	}
	// A ZIP that is not an office file (no recognized content parts) also declines.
	if _, _, ok := extract.Text(makeOOXML(map[string]string{"random/file.txt": "hi"})); ok {
		t.Error("a non-office ZIP must not be treated as a document")
	}
	// A PDF with no extractable text (image-only/empty) declines rather than erroring.
	if _, _, ok := extract.Text([]byte("%PDF-1.4\nno objects here\n%%EOF")); ok {
		t.Error("an unparseable PDF must decline, not panic or falsely succeed")
	}
}

// TestScanPipelineExtractsDocuments proves the scanner scans document contents
// when extraction is on, and falls back to skipping them as binary when off.
func TestScanPipelineExtractsDocuments(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	docx := makeOOXML(map[string]string{
		"word/document.xml": `<w:document><w:body><w:p><w:r><w:t>card 4111111111111111</w:t></w:r></w:p></w:body></w:document>`,
	})
	pdf := makePDF("card 4111111111111111")

	mem := provider.NewMemStore()
	mem.Put("b", "report.docx", docx)
	mem.Put("b", "statement.pdf", pdf)

	// Extraction on: both documents are decoded and scanned.
	sc := scanner.New(mem, scanner.Config{Bucket: "b", SkipBinary: true, ExtractDocs: true})
	objs, _, _, _ := sc.Inventory(context.Background())
	res := collect(t, sc, objs, eng)

	for _, key := range []string{"report.docx", "statement.pdf"} {
		r := res[key]
		if r.Extracted == "" {
			t.Errorf("%s: expected Extracted to be set, got empty (skipped=%v)", key, r.Skipped)
		}
		if !hasCategory(r.Findings, "credit_card") {
			t.Errorf("%s: expected a credit_card finding, got %+v", key, r.Findings)
		}
		for _, f := range r.Findings {
			if strings.Contains(f.Masked, "4111111111111111") {
				t.Errorf("%s: raw card value leaked into masked output", key)
			}
		}
	}

	// Extraction off: no document is decoded. The docx (a real ZIP, so its
	// bytes carry NULs) additionally trips the binary-skip heuristic.
	sc = scanner.New(mem, scanner.Config{Bucket: "b", SkipBinary: true, ExtractDocs: false})
	objs, _, _, _ = sc.Inventory(context.Background())
	res = collect(t, sc, objs, eng)
	for _, key := range []string{"report.docx", "statement.pdf"} {
		if r := res[key]; r.Extracted != "" {
			t.Errorf("%s with extraction off: want no extraction, got extracted=%q", key, r.Extracted)
		}
	}
	if r := res["report.docx"]; !r.Skipped || r.SkipReason != "binary content" {
		t.Errorf("report.docx with extraction off should be skipped as binary, got skipped=%v reason=%q",
			r.Skipped, r.SkipReason)
	}
}
