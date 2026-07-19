// Package scanner lists and streams S3 objects under a prefix, running the PII
// engine over each one. All S3 API calls pass through a shared token-bucket
// rate limiter so a large scan does not trip S3 request throttling.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/time/rate"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/cost"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/engine"
)

// Analyzer runs a secondary detector (e.g. the privyscope NER sidecar) over an
// object's text, returning findings tagged as source=ner.
type Analyzer interface {
	Analyze(ctx context.Context, text string) ([]engine.Finding, error)
}

// Config controls listing, throttling, and per-object limits.
type Config struct {
	Bucket         string
	Prefix         string
	MaxObjectBytes int64   // objects larger than this are skipped (0 = no limit)
	MaxObjects     int64   // stop the LIST after this many objects (0 = no cap; per-bucket sampling)
	ScanBytesCap   int64   // read at most this many bytes per object (0 = whole object)
	RequestsPerSec float64 // shared S3 API rate (0 = unlimited)
	Burst          int
	Concurrency    int
	SkipBinary     bool

	// NER, when set, is invoked per object and its findings are merged with the
	// regex findings (regex wins on overlap). NERMaxBytes caps the text sent.
	NER         Analyzer
	NERMaxBytes int64
}

// Object is a single S3 object discovered during the inventory pass.
type Object struct {
	Key  string
	Size int64
}

// Result is the outcome of scanning one object.
type Result struct {
	Key        string
	Size       int64
	BytesRead  int64
	Skipped    bool
	SkipReason string
	Err        error // object-level failure (LIST/GET/read)
	NERErr     error // NER call failed; regex findings are still valid
	Findings   []engine.Finding
}

// Scanner holds the S3 client and shared limiter.
type Scanner struct {
	s3      *s3.Client
	cfg     Config
	limiter *rate.Limiter
}

// New builds a Scanner. A RequestsPerSec of 0 disables client-side limiting
// (the SDK's adaptive retry still applies).
func New(s3c *s3.Client, cfg Config) *Scanner {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 4
	}
	var lim *rate.Limiter
	if cfg.RequestsPerSec > 0 {
		burst := cfg.Burst
		if burst < 1 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(cfg.RequestsPerSec), burst)
	}
	return &Scanner{s3: s3c, cfg: cfg, limiter: lim}
}

func (s *Scanner) wait(ctx context.Context) error {
	if s.limiter == nil {
		return nil
	}
	return s.limiter.Wait(ctx)
}

// Inventory performs the LIST pass, returning the objects that will be scanned
// (after the size filter) and a cost tally. Objects above MaxObjectBytes are
// excluded from the returned list and counted separately as skipped.
func (s *Scanner) Inventory(ctx context.Context) (objects []Object, inv cost.Inventory, skippedLarge int64, err error) {
	p := s3.NewListObjectsV2Paginator(s.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.Bucket),
		Prefix: aws.String(s.cfg.Prefix),
	})
	for p.HasMorePages() {
		if err = s.wait(ctx); err != nil {
			return nil, inv, 0, err
		}
		page, perr := p.NextPage(ctx)
		if perr != nil {
			return nil, inv, 0, fmt.Errorf("s3:ListObjectsV2 on %s/%s: %w", s.cfg.Bucket, s.cfg.Prefix, perr)
		}
		inv.ListRequests++
		for _, o := range page.Contents {
			size := aws.ToInt64(o.Size)
			if s.cfg.MaxObjectBytes > 0 && size > s.cfg.MaxObjectBytes {
				skippedLarge++
				continue
			}
			objects = append(objects, Object{Key: aws.ToString(o.Key), Size: size})
			inv.Objects++
			inv.Bytes += size
			if s.cfg.MaxObjects > 0 && inv.Objects >= s.cfg.MaxObjects {
				return objects, inv, skippedLarge, nil
			}
		}
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

	if err := s.wait(ctx); err != nil {
		res.Err = err
		return res
	}
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(obj.Key),
	})
	if err != nil {
		res.Err = fmt.Errorf("s3:GetObject %s: %w", obj.Key, err)
		return res
	}
	defer out.Body.Close()

	var reader io.Reader = out.Body
	if s.cfg.ScanBytesCap > 0 {
		reader = io.LimitReader(out.Body, s.cfg.ScanBytesCap)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		res.Err = fmt.Errorf("read %s: %w", obj.Key, err)
		return res
	}
	res.BytesRead = int64(len(data))

	if s.cfg.SkipBinary && looksBinary(data) {
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
