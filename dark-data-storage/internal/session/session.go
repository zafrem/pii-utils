// Package session manages a durable, resumable scan run backed by a directory
// on disk:
//
//	<dir>/manifest.json   run metadata + fingerprint (guards against resuming a
//	                      different target into the same directory)
//	<dir>/results.jsonl   append-only ledger, one JSON Record per processed
//	                      object, flushed as it happens — the continuous report
//	                      and the resume checkpoint in one file
//	<dir>/summary.json    aggregate, (re)written at finish or on interrupt
//
// Opening a directory that already holds a manifest resumes it: the ledger is
// replayed to rebuild the set of completed keys and to re-seed the aggregate,
// then new records are appended to the same ledger.
package session

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zafrem/pii-utils/dark-data-storage/internal/report"
)

const (
	manifestName = "manifest.json"
	resultsName  = "results.jsonl"
	summaryName  = "summary.json"
	formatVer    = 1
	syncEvery    = 64 // fsync the ledger every N appends
)

// Meta identifies what a session is scanning. Its fingerprint must match on
// resume.
type Meta struct {
	Bucket     string
	Prefix     string
	Region     string
	Locations  []string
	Categories []string
}

// Fingerprint is a stable hash of the target and pattern selection.
func (m Meta) Fingerprint() string {
	loc := append([]string(nil), m.Locations...)
	cat := append([]string(nil), m.Categories...)
	sort.Strings(loc)
	sort.Strings(cat)
	h := sha256.Sum256([]byte(strings.Join([]string{
		m.Bucket, m.Prefix, strings.Join(loc, ","), strings.Join(cat, ","),
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

type manifest struct {
	Version     int       `json:"version"`
	Bucket      string    `json:"bucket"`
	Prefix      string    `json:"prefix"`
	Region      string    `json:"region"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Runs        int       `json:"runs"`
}

// Session is an open, appendable scan run.
type Session struct {
	dir  string
	meta Meta

	mu     sync.Mutex
	ledger *os.File
	enc    *json.Encoder
	writes int
	done   map[string]struct{}
	rep    *report.Report
}

// Open creates or resumes a session directory. When fresh is true any existing
// ledger/manifest is archived aside and a new run is started. The returned
// resumed flag reports whether prior progress was loaded.
func Open(dir string, meta Meta, fresh bool) (s *Session, resumed bool, err error) {
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, fmt.Errorf("create session dir: %w", err)
	}
	manPath := filepath.Join(dir, manifestName)
	resPath := filepath.Join(dir, resultsName)

	if fresh {
		if err = archiveExisting(dir); err != nil {
			return nil, false, err
		}
	}

	man, haveManifest, err := readManifest(manPath)
	if err != nil {
		return nil, false, err
	}

	s = &Session{
		dir:  dir,
		meta: meta,
		done: map[string]struct{}{},
		rep:  report.New(meta.Bucket, meta.Prefix, meta.Region),
	}
	s.rep.ResultsFile = resultsName

	if haveManifest {
		if man.Fingerprint != meta.Fingerprint() {
			return nil, false, fmt.Errorf(
				"session %q was created for a different target/pattern set (fingerprint %s ≠ %s); "+
					"use --fresh to start over or a different --out directory",
				dir, man.Fingerprint, meta.Fingerprint())
		}
		if err = s.replay(resPath); err != nil {
			return nil, false, fmt.Errorf("replay ledger: %w", err)
		}
		s.rep.SetStartedAt(man.CreatedAt)
		resumed = len(s.done) > 0
	} else {
		man = manifest{
			Version:     formatVer,
			Bucket:      meta.Bucket,
			Prefix:      meta.Prefix,
			Region:      meta.Region,
			Fingerprint: meta.Fingerprint(),
			CreatedAt:   time.Now(),
		}
	}

	// Open the ledger for appending.
	f, err := os.OpenFile(resPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, false, fmt.Errorf("open ledger: %w", err)
	}
	s.ledger = f
	s.enc = json.NewEncoder(f) // one compact JSON object per line

	man.Runs++
	man.UpdatedAt = time.Now()
	if err = writeManifest(manPath, man); err != nil {
		_ = f.Close()
		return nil, false, err
	}
	return s, resumed, nil
}

// replay reads an existing ledger, rebuilding the completed-key set and
// re-seeding the aggregate. Truncated trailing lines (from a hard crash) are
// tolerated: a final partial line is ignored.
func (s *Session) replay(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				var rec report.Record
				if uerr := json.Unmarshal([]byte(trimmed), &rec); uerr != nil {
					// A malformed final line means the previous run died
					// mid-write; ignore it and stop.
					if err == io.EOF {
						break
					}
					continue
				}
				if rec.Key != "" {
					s.done[rec.Key] = struct{}{}
					s.rep.AddRecord(rec)
				}
			}
		}
		if err != nil {
			break // io.EOF or read error; either way we stop
		}
	}
	return nil
}

// Done reports whether an object key has already been processed in this session.
func (s *Session) Done(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.done[key]
	return ok
}

// CompletedCount returns how many objects were processed in prior runs.
func (s *Session) CompletedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.done)
}

// Record appends one Record to the ledger, flushing so it survives an
// interrupt, and folds it into the aggregate. Safe for concurrent callers.
func (s *Session) Record(rec report.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(rec); err != nil { // Encode writes the trailing '\n'
		return err
	}
	s.done[rec.Key] = struct{}{}
	s.rep.AddRecord(rec)
	s.writes++
	if s.writes%syncEvery == 0 {
		_ = s.ledger.Sync()
	}
	return nil
}

// Report exposes the live aggregate (for rendering the summary).
func (s *Session) Report() *report.Report { return s.rep }

// Dir returns the session directory.
func (s *Session) Dir() string { return s.dir }

// SummaryPath is where WriteSummary writes.
func (s *Session) SummaryPath() string { return filepath.Join(s.dir, summaryName) }

// WriteSummary finalizes the aggregate and writes summary.json (and optionally a
// copy to extraPath). complete indicates whether the whole scan finished.
func (s *Session) WriteSummary(complete bool, extraPath string) error {
	s.rep.Finish(complete)
	if err := s.rep.WriteJSON(s.SummaryPath()); err != nil {
		return err
	}
	if extraPath != "" {
		if err := s.rep.WriteJSON(extraPath); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes the ledger.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledger == nil {
		return nil
	}
	_ = s.ledger.Sync()
	err := s.ledger.Close()
	s.ledger = nil
	return err
}

func readManifest(path string) (manifest, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return manifest{}, false, nil
		}
		return manifest{}, false, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return manifest{}, false, fmt.Errorf("corrupt manifest %q: %w", path, err)
	}
	return m, true, nil
}

func writeManifest(path string, m manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// archiveExisting renames a prior ledger and manifest aside with a timestamp so
// --fresh does not destroy earlier results.
func archiveExisting(dir string) error {
	stamp := time.Now().Format("20060102-150405")
	for _, name := range []string{resultsName, manifestName, summaryName} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			if err := os.Rename(p, p+"."+stamp+".bak"); err != nil {
				return fmt.Errorf("archive %s: %w", name, err)
			}
		}
	}
	return nil
}
