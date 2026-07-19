// Package extract turns rich document containers into the plain text hidden
// inside them so the PII engine can scan their contents. Office Open XML files
// (.docx/.xlsx/.pptx) are ZIP archives of XML and are handled with the standard
// library; PDFs are parsed with ledongthuc/pdf. Everything else is left to the
// caller to scan as raw bytes.
//
// Extraction is best-effort and read-only: it never writes, never reaches the
// network, and returns ok=false (rather than an error) whenever a document
// cannot be turned into text — encrypted, image-only/scanned, or corrupt — so
// the caller falls back to its normal binary handling.
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	"github.com/ledongthuc/pdf"
)

// Magic byte prefixes for the containers we understand.
var (
	magicPDF = []byte("%PDF-")
	magicZIP = []byte("PK\x03\x04") // also empty-archive PK\x05\x06 / spanned PK\x07\x08, unusual for office files
)

// IsDoc reports whether the leading bytes look like a document extract.Text can
// read (a PDF or an OOXML office file). It lets a caller decide, from a cheap
// peek, whether to buffer the whole object for extraction instead of applying a
// byte cap that would truncate the container into something unparseable.
func IsDoc(magic []byte) bool {
	return bytes.HasPrefix(magic, magicPDF) || bytes.HasPrefix(magic, magicZIP)
}

// Text extracts the visible text of a supported document. kind is one of
// "pdf", "docx", "xlsx", or "pptx". ok is false when data is not a recognized
// document, or when no text could be recovered (encrypted, scanned image, or
// corrupt) — in that case the caller should treat the bytes as it normally
// would.
func Text(data []byte) (text, kind string, ok bool) {
	switch {
	case bytes.HasPrefix(data, magicPDF):
		t := pdfText(data)
		if strings.TrimSpace(t) == "" {
			return "", "", false
		}
		return t, "pdf", true
	case bytes.HasPrefix(data, magicZIP):
		t, k := ooxmlText(data)
		if k == "" || strings.TrimSpace(t) == "" {
			return "", "", false
		}
		return t, k, true
	}
	return "", "", false
}

// pdfText pulls the plain text out of a PDF. The underlying parser panics on
// some malformed inputs, so it is wrapped in a recover: a bad PDF yields "" and
// the caller falls back to binary handling rather than crashing the scan.
func pdfText(data []byte) (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ""
	}
	rd, err := r.GetPlainText()
	if err != nil {
		return ""
	}
	var b strings.Builder
	if _, err := io.Copy(&b, rd); err != nil {
		return ""
	}
	return b.String()
}

// ooxmlText reads an Office Open XML file (a ZIP of XML parts) and returns the
// concatenated text of its content parts along with the detected kind.
func ooxmlText(data []byte) (text, kind string) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", ""
	}
	var b strings.Builder
	for _, f := range zr.File {
		if !isContentPart(f.Name) {
			continue
		}
		if kind == "" {
			kind = classify(f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		xmlText(rc, &b)
		rc.Close()
	}
	return b.String(), kind
}

// isContentPart reports whether an OOXML archive member holds user-authored
// text (as opposed to styles, themes, relationships, and other scaffolding).
func isContentPart(name string) bool {
	switch {
	case strings.HasPrefix(name, "word/document.xml"),
		strings.HasPrefix(name, "word/header"),
		strings.HasPrefix(name, "word/footer"),
		strings.HasPrefix(name, "word/footnotes.xml"),
		strings.HasPrefix(name, "word/endnotes.xml"),
		strings.HasPrefix(name, "word/comments.xml"): // .docx
		return true
	case name == "xl/sharedStrings.xml",
		strings.HasPrefix(name, "xl/worksheets/sheet"): // .xlsx
		return true
	case strings.HasPrefix(name, "ppt/slides/slide"),
		strings.HasPrefix(name, "ppt/notesSlides/notesSlide"): // .pptx
		return true
	}
	return false
}

// classify maps a content-part path to the office file kind.
func classify(name string) string {
	switch {
	case strings.HasPrefix(name, "word/"):
		return "docx"
	case strings.HasPrefix(name, "xl/"):
		return "xlsx"
	case strings.HasPrefix(name, "ppt/"):
		return "pptx"
	}
	return ""
}

// xmlText appends the character data of an XML part to b, inserting a space
// after every element so words from adjacent runs/cells do not fuse together
// and a newline at paragraph and table-row boundaries so line-oriented findings
// keep meaningful line numbers. It never fails: a malformed part just ends the
// walk early with whatever text was recovered.
func xmlText(r io.Reader, b *strings.Builder) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.CharData:
			if len(t) > 0 {
				b.Write(t)
				b.WriteByte(' ')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "p", "tr", "row": // paragraph / table row (word, powerpoint, excel)
				b.WriteByte('\n')
			}
		}
	}
}
