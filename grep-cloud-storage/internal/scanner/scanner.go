// Package scanner lists and streams objects under a prefix through a
// provider.Store, running the PII engine over each one. It is provider-neutral:
// the Store owns API calls and rate limiting, the scanner owns concurrency,
// per-object limits, and the regex/NER pipeline.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/cost"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/engine"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/extract"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/provider"
)

// Analyzer runs a secondary detector (e.g. the privyscope NER sidecar) over an
// object's text, returning findings tagged as source=ner.
type Analyzer interface {
	Analyze(ctx context.Context, text string) ([]engine.Finding, error)
}

// Object is a single object discovered during the inventory pass.
type Object = provider.Object

// Config controls listing scope and per-object limits. Rate limiting lives in
// the provider.Store, not here.
type Config struct {
	Bucket         string
	Prefix         string
	MaxObjectBytes int64 // objects larger than this are skipped (0 = no limit)
	MaxObjects     int64 // stop the LIST after this many objects (0 = no cap; per-bucket sampling)
	ScanBytesCap   int64 // read at most this many bytes per object (0 = whole object)
	Concurrency    int
	SkipBinary     bool
	ExtractDocs    bool // extract text from PDF/office documents instead of skipping them as binary

	// NER, when set, is invoked per object and its findings are merged with the
	// regex findings (regex wins on overlap). NERMaxBytes caps the text sent.
	NER         Analyzer
	NERMaxBytes int64
}

// Result is the outcome of scanning one object.
type Result struct {
	Key        string
	Size       int64
	BytesRead  int64
	Skipped    bool
	SkipReason string
	Extracted  string // non-empty when the object was decoded from a document ("pdf"/"docx"/"xlsx"/"pptx")
	Err        error  // object-level failure (LIST/GET/read)
	NERErr     error  // NER call failed; regex findings are still valid
	Findings   []engine.Finding
}

// Scanner runs the object-storage read + PII pipeline over a Store.
type Scanner struct {
	store provider.Store
	cfg   Config
}

// New builds a Scanner over the given Store.
func New(store provider.Store, cfg Config) *Scanner {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 4
	}
	return &Scanner{store: store, cfg: cfg}
}

// Inventory performs the LIST pass, returning the objects that will be scanned
// (after the size filter) and a cost tally. Objects above MaxObjectBytes are
// excluded from the returned list and counted separately as skipped. Listing
// stops early once MaxObjects have been collected.
func (s *Scanner) Inventory(ctx context.Context) (objects []Object, inv cost.Inventory, skippedLarge int64, err error) {
	err = s.store.List(ctx, s.cfg.Bucket, s.cfg.Prefix, func(page []Object) error {
		inv.ListRequests++
		for _, o := range page {
			if s.cfg.MaxObjectBytes > 0 && o.Size > s.cfg.MaxObjectBytes {
				skippedLarge++
				continue
			}
			objects = append(objects, o)
			inv.Objects++
			inv.Bytes += o.Size
			if s.cfg.MaxObjects > 0 && inv.Objects >= s.cfg.MaxObjects {
				return provider.ErrStop
			}
		}
		return nil
	})
	if err != nil {
		return nil, cost.Inventory{}, 0, err
	}
	return objects, inv, skippedLarge, nil
}

// Scan downloads and scans the given objects concurrently, invoking onResult for
// each (from multiple goroutines — onResult must be safe for concurrent use).
func (s *Scanner) Scan(ctx context.Context, objects []Object, eng *engine.Engine, onResult func(Result)) error {
	jobs := make(chan Object)
	var wg sync.WaitGroup
	var mu sync.Mutex // serializes onResult so callers can stay simple

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range jobs {
				res := s.scanOne(ctx, obj, eng)
				mu.Lock()
				onResult(res)
				mu.Unlock()
			}
		}()
	}

	var feedErr error
feed:
	for _, obj := range objects {
		select {
		case <-ctx.Done():
			feedErr = ctx.Err()
			break feed
		case jobs <- obj:
		}
	}
	close(jobs)
	wg.Wait()
	return feedErr
}

func (s *Scanner) scanOne(ctx context.Context, obj Object, eng *engine.Engine) Result {
	res := Result{Key: obj.Key, Size: obj.Size}

	body, err := s.store.Open(ctx, s.cfg.Bucket, obj.Key)
	if err != nil {
		res.Err = err
		return res
	}
	defer body.Close()

	// Peek the leading bytes so a document container can be buffered whole for
	// extraction: a byte cap that truncated a PDF/ZIP would leave it unparseable.
	br := bufio.NewReader(body)
	magic, _ := br.Peek(8)
	isDoc := s.cfg.ExtractDocs && extract.IsDoc(magic)

	var reader io.Reader = br
	switch {
	case isDoc && s.cfg.MaxObjectBytes > 0:
		reader = io.LimitReader(br, s.cfg.MaxObjectBytes) // bound memory; cap does not apply to docs
	case !isDoc && s.cfg.ScanBytesCap > 0:
		reader = io.LimitReader(br, s.cfg.ScanBytesCap)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		res.Err = fmt.Errorf("read %s: %w", obj.Key, err)
		return res
	}
	res.BytesRead = int64(len(data))

	// Turn a recognized document into its plain text; on failure (encrypted,
	// scanned image, corrupt) fall through to normal binary handling.
	if isDoc {
		if text, kind, ok := extract.Text(data); ok {
			res.Extracted = kind
			data = []byte(text)
		}
	}

	if res.Extracted == "" && s.cfg.SkipBinary && looksBinary(data) {
		res.Skipped = true
		res.SkipReason = "binary content"
		return res
	}

	res.Findings = eng.Scan(data)

	if s.cfg.NER != nil {
		text := string(data)
		if s.cfg.NERMaxBytes > 0 && int64(len(text)) > s.cfg.NERMaxBytes {
			// Trim to the cap, then drop a possibly-split trailing rune so the
			// sidecar always receives valid UTF-8.
			text = strings.ToValidUTF8(text[:s.cfg.NERMaxBytes], "")
		}
		nerFindings, err := s.cfg.NER.Analyze(ctx, text)
		if err != nil {
			res.NERErr = err
		} else {
			res.Findings = engine.Merge(res.Findings, nerFindings)
		}
	}
	return res
}

// looksBinary reports whether the first 512 bytes contain a NUL, a cheap and
// effective heuristic for non-text blobs.
func looksBinary(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
