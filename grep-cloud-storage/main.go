// Command grep-aws-s3 scans objects under an S3 prefix for PII using the
// zafrem/pii-pattern-engine rules. Before downloading anything it verifies
// whether the bucket is in the caller's account, estimates cost and warns on
// large volumes, and throttles all S3 calls to avoid request-rate errors.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/awsx"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/cost"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/engine"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/ner"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/report"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/scanner"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/session"
)

type options struct {
	bucket       string
	prefix       string
	region       string
	patternsDir  string
	locations    string
	categories   string
	maxObjectMB  int64
	scanCapKB    int64
	rps          float64
	burst        int
	concurrency  int
	scanBinary   bool
	requireSame  bool
	assumeYes    bool
	estimateOnly bool
	jsonOut      string
	out          string
	fresh        bool
	ner          bool
	nerEndpoint  string
	nerMaxKB     int64
	maxAttempts  int
	thObjects    int64
	thGB         float64
	thUSD        float64
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var o options
	fs := flag.NewFlagSet("grep-aws-s3", flag.ContinueOnError)
	fs.StringVar(&o.bucket, "bucket", "", "S3 bucket name (or pass s3://bucket/prefix as an argument)")
	fs.StringVar(&o.prefix, "prefix", "", "key prefix to scan")
	fs.StringVar(&o.region, "region", "", "AWS region (default: from environment/profile)")
	fs.StringVar(&o.patternsDir, "patterns", "", "path to pii-pattern-engine/regex (default: auto-detect submodule)")
	fs.StringVar(&o.locations, "locations", "", "comma-separated pattern namespaces to include (e.g. comm,kr,us)")
	fs.StringVar(&o.categories, "categories", "", "comma-separated categories to include (e.g. credit_card,email)")
	fs.Int64Var(&o.maxObjectMB, "max-object-mb", 100, "skip objects larger than this many MB (0 = no limit)")
	fs.Int64Var(&o.scanCapKB, "scan-cap-kb", 0, "read at most this many KB per object (0 = whole object)")
	fs.Float64Var(&o.rps, "rps", 20, "max S3 API requests per second (0 = unlimited)")
	fs.IntVar(&o.burst, "burst", 5, "rate limiter burst size")
	fs.IntVar(&o.concurrency, "concurrency", 8, "number of concurrent object downloads")
	fs.BoolVar(&o.scanBinary, "scan-binary", false, "also scan objects that look binary")
	fs.BoolVar(&o.requireSame, "require-same-account", false, "abort if the bucket is not owned by the calling account")
	fs.BoolVar(&o.assumeYes, "yes", false, "proceed past the cost warning without prompting")
	fs.BoolVar(&o.estimateOnly, "estimate-only", false, "list and estimate cost, then exit without downloading")
	fs.StringVar(&o.jsonOut, "json", "", "also write a copy of the summary to this file")
	fs.StringVar(&o.out, "out", "", "session directory for the resumable ledger (default: auto-derived from target)")
	fs.BoolVar(&o.fresh, "fresh", false, "ignore any prior progress in the session dir and start over (existing files archived)")
	fs.BoolVar(&o.ner, "ner", false, "enable the privyscope NER stage (requires the sidecar; see privyscope-ner-server/)")
	fs.StringVar(&o.nerEndpoint, "ner-endpoint", "http://127.0.0.1:8080", "base URL of the privyscope NER sidecar")
	fs.Int64Var(&o.nerMaxKB, "ner-max-kb", 256, "cap text (KB) sent to NER per object (0 = whole object)")
	fs.IntVar(&o.maxAttempts, "max-retries", 10, "max SDK retry attempts per request (adaptive backoff)")
	fs.Int64Var(&o.thObjects, "warn-objects", cost.DefaultThresholds.Objects, "warn when object count reaches this (0 = off)")
	fs.Float64Var(&o.thGB, "warn-gb", cost.DefaultThresholds.GB, "warn when data volume reaches this many GB (0 = off)")
	fs.Float64Var(&o.thUSD, "warn-usd", cost.DefaultThresholds.USD, "warn when estimated cost reaches this many USD (0 = off)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: grep-aws-s3 [flags] s3://bucket[/prefix]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if err := applyTarget(&o, fs.Args()); err != nil {
		return err
	}
	if o.bucket == "" {
		fs.Usage()
		return errors.New("no bucket specified")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Load detection patterns.
	patternsDir, err := resolvePatternsDir(o.patternsDir)
	if err != nil {
		return err
	}
	eng, err := engine.Load(patternsDir, engine.Options{
		Locations:  splitCSV(o.locations),
		Categories: splitCSV(o.categories),
	})
	if err != nil {
		return err
	}
	fmt.Printf("Loaded %d patterns from %s\n", eng.PatternCount(), patternsDir)
	if unresolved := eng.UnresolvedVerifications(); len(unresolved) > 0 {
		fmt.Printf("  note: %d verification function(s) not found, running those rules as regex-only: %s\n",
			len(unresolved), strings.Join(unresolved, ", "))
	}

	// NER sidecar (optional). Preflight the health endpoint so a missing or
	// unhealthy sidecar fails fast — before any AWS calls or S3 spend.
	var nerAnalyzer scanner.Analyzer
	if o.ner {
		nerClient := ner.New(o.nerEndpoint, 2*time.Minute)
		langs, hasNER, perr := nerClient.Ping(ctx)
		if perr != nil {
			return fmt.Errorf("--ner requested but %w\n  start it with: cd privyscope-ner-server && python server.py", perr)
		}
		if !hasNER {
			fmt.Printf("⚠  NER sidecar is running in regex-only mode (no model weights loaded)\n")
		}
		fmt.Printf("NER: %s (languages: %s)\n", o.nerEndpoint, strings.Join(langs, ", "))
		nerAnalyzer = nerClient
	}

	// 2. Build clients and identify the caller.
	clients, err := awsx.New(ctx, o.region, o.maxAttempts)
	if err != nil {
		return err
	}
	caller, err := clients.WhoAmI(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Caller: account %s (%s)\n", caller.Account, caller.ARN)

	// 3. Same-account ownership check.
	own := clients.CheckBucketOwnership(ctx, o.bucket, caller)
	sameAccountLabel := "unknown"
	switch {
	case own.Indeterminate:
		fmt.Printf("⚠  same-account check: INDETERMINATE — %s\n", own.Reason)
	case own.SameAccount:
		sameAccountLabel = "yes"
		fmt.Printf("✓  same-account check: OK — %s\n", own.Reason)
	default:
		sameAccountLabel = "no"
		fmt.Printf("⚠  same-account check: CROSS-ACCOUNT — %s\n", own.Reason)
	}
	if !own.SameAccount && o.requireSame {
		return errors.New("aborting: --require-same-account set and bucket is not confirmed same-account")
	}

	// 4. Inventory (LIST) pass.
	sc := scanner.New(clients.S3, scanner.Config{
		Bucket:         o.bucket,
		Prefix:         o.prefix,
		MaxObjectBytes: o.maxObjectMB * 1024 * 1024,
		ScanBytesCap:   o.scanCapKB * 1024,
		RequestsPerSec: o.rps,
		Burst:          o.burst,
		Concurrency:    o.concurrency,
		SkipBinary:     !o.scanBinary,
		NER:            nerAnalyzer,
		NERMaxBytes:    o.nerMaxKB * 1024,
	})
	fmt.Printf("Listing s3://%s/%s ...\n", o.bucket, o.prefix)
	objects, inv, skippedLarge, err := sc.Inventory(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Found %d objects (%d skipped: over size limit)\n", inv.Objects, skippedLarge)
	if inv.Objects == 0 {
		fmt.Println("Nothing to scan.")
		return nil
	}

	// estimate-only stops here without creating a session (no side effects).
	if o.estimateOnly {
		est := cost.ComputeAWS(inv, own.SameAccount)
		fmt.Println("Estimated cost (full inventory):")
		fmt.Println(est.Summary())
		return nil
	}

	// 5. Open (or resume) the durable session.
	meta := session.Meta{
		Bucket:     o.bucket,
		Prefix:     o.prefix,
		Region:     clients.Region,
		Locations:  splitCSV(o.locations),
		Categories: splitCSV(o.categories),
	}
	outDir := o.out
	if outDir == "" {
		outDir = defaultOutDir(meta)
	}
	sess, resumed, err := session.Open(outDir, meta, o.fresh)
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Report().SameAccount = sameAccountLabel

	// Subtract already-completed objects (resume).
	remaining := objects[:0:0]
	var remainingBytes int64
	for _, obj := range objects {
		if resumed && sess.Done(obj.Key) {
			continue
		}
		remaining = append(remaining, obj)
		remainingBytes += obj.Size
	}
	if resumed {
		fmt.Printf("Resuming session %s: %d already done, %d remaining\n", sess.Dir(), sess.CompletedCount(), len(remaining))
	} else {
		fmt.Printf("Session: %s\n", sess.Dir())
	}
	if len(remaining) == 0 {
		fmt.Println("All listed objects already processed; nothing to do.")
		if err := sess.WriteSummary(true, o.jsonOut); err != nil {
			return err
		}
		fmt.Print(sess.Report().Summary())
		return nil
	}

	// 6. Cost estimate + warning gate (on the remaining work).
	est := cost.ComputeAWS(cost.Inventory{Objects: int64(len(remaining)), Bytes: remainingBytes, ListRequests: inv.ListRequests}, own.SameAccount)
	fmt.Println("Estimated cost (remaining):")
	fmt.Println(est.Summary())
	if exceeds, reasons := est.ExceedsAny(cost.Thresholds{Objects: o.thObjects, GB: o.thGB, USD: o.thUSD}); exceeds {
		fmt.Printf("⚠  LARGE SCAN: %s\n", strings.Join(reasons, "; "))
		if !o.assumeYes {
			ok, perr := confirm("Proceed with the scan?")
			if perr != nil {
				return perr
			}
			if !ok {
				fmt.Println("Aborted by user (progress so far is saved; re-run to resume).")
				return nil
			}
		}
	}

	// 7. Scan — each result is appended to the ledger as it completes.
	total := len(remaining)
	var processed, findingsSoFar, nerErrors int
	onResult := func(res scanner.Result) {
		rec := report.Record{
			Key:          res.Key,
			Size:         res.Size,
			BytesScanned: res.BytesRead,
			Skipped:      res.Skipped,
			SkipReason:   res.SkipReason,
			Findings:     res.Findings,
			ScannedAt:    time.Now(),
		}
		if res.Err != nil {
			rec.Error = res.Err.Error()
		}
		if werr := sess.Record(rec); werr != nil {
			fmt.Fprintf(os.Stderr, "warning: ledger write failed for %s: %v\n", res.Key, werr)
		}
		processed++
		findingsSoFar += len(res.Findings)
		for _, f := range res.Findings {
			fmt.Printf("  [%-8s] %s → %s (%s, conf %d) line %d\n", f.Severity, res.Key, f.Category, f.PatternID, f.Confidence, f.Line)
		}
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "  error: %s: %s\n", res.Key, res.Err)
		}
		if res.NERErr != nil {
			nerErrors++
			if nerErrors <= 5 { // avoid flooding if the sidecar died mid-scan
				fmt.Fprintf(os.Stderr, "  ner-error: %s: %s\n", res.Key, res.NERErr)
			}
		}
		if processed%100 == 0 || processed == total {
			fmt.Fprintf(os.Stderr, "  ...%d/%d processed, %d findings so far\n", processed, total, findingsSoFar)
		}
	}

	fmt.Printf("Scanning at up to %.0f req/s with %d workers ...\n", o.rps, o.concurrency)
	scanErr := sc.Scan(ctx, remaining, eng, onResult)

	// 8. Finalize. Scan drains all remaining objects unless the context was
	// cancelled (Ctrl-C), so cancellation is the sole "incomplete" signal.
	complete := ctx.Err() == nil
	if err := sess.WriteSummary(complete, o.jsonOut); err != nil {
		return err
	}
	fmt.Println()
	fmt.Print(sess.Report().Summary())
	if nerErrors > 0 {
		fmt.Printf("  ⚠ NER errors: %d object(s) scanned regex-only (sidecar issue)\n", nerErrors)
	}
	fmt.Printf("  ledger:  %s\n  summary: %s\n", filepath.Join(sess.Dir(), "results.jsonl"), sess.SummaryPath())

	if !complete {
		fmt.Printf("\nInterrupted — progress is saved. Resume with the same command:\n  grep-aws-s3 --out %s %s\n",
			sess.Dir(), targetString(o))
	}
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		return scanErr
	}
	return nil
}

// defaultOutDir derives a deterministic session directory from the target and
// pattern selection, so re-running the same command resumes automatically while
// a different selection lands in its own directory.
func defaultOutDir(meta session.Meta) string {
	slug := meta.Bucket
	if meta.Prefix != "" {
		slug += "-" + meta.Prefix
	}
	return fmt.Sprintf("s3grep-%s-%s", sanitizeSlug(slug), meta.Fingerprint())
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = out[:60]
	}
	if out == "" {
		out = "bucket"
	}
	return out
}

func targetString(o options) string {
	if o.prefix == "" {
		return "s3://" + o.bucket
	}
	return "s3://" + o.bucket + "/" + o.prefix
}

// applyTarget parses an optional s3://bucket/prefix positional argument, which
// takes precedence over --bucket/--prefix when present.
func applyTarget(o *options, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("unexpected extra arguments: %v", args[1:])
	}
	t := strings.TrimPrefix(args[0], "s3://")
	bucket, prefix, _ := strings.Cut(t, "/")
	if bucket == "" {
		return fmt.Errorf("invalid S3 target %q", args[0])
	}
	o.bucket = bucket
	o.prefix = prefix
	return nil
}

// resolvePatternsDir finds the engine's regex directory: explicit flag, then
// PII_PATTERNS_DIR, then the submodule relative to the working directory or the
// executable.
func resolvePatternsDir(flagVal string) (string, error) {
	candidates := []string{}
	if flagVal != "" {
		candidates = append(candidates, flagVal)
	}
	if env := os.Getenv("PII_PATTERNS_DIR"); env != "" {
		candidates = append(candidates, env)
	}
	if wd, err := os.Getwd(); err == nil {
		// Walk up looking for a sibling pii-pattern-engine checkout.
		dir := wd
		for i := 0; i < 6; i++ {
			candidates = append(candidates, filepath.Join(dir, "pii-pattern-engine", "regex"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(base, "pii-pattern-engine", "regex"),
			filepath.Join(base, "..", "pii-pattern-engine", "regex"),
		)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf("could not locate pattern directory; pass --patterns or set PII_PATTERNS_DIR (tried: %s)",
		strings.Join(candidates, ", "))
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func confirm(prompt string) (bool, error) {
	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		// Non-interactive stdin: refuse to guess.
		return false, errors.New("cost warning triggered and stdin is not a terminal; re-run with --yes to proceed")
	}
	fmt.Printf("%s [y/N]: ", prompt)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false, sc.Err()
	}
	ans := strings.ToLower(strings.TrimSpace(sc.Text()))
	return ans == "y" || ans == "yes", nil
}
