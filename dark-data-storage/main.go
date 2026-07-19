// Command dark-data-storage discovers ungoverned ("dark") cloud storage and
// scans it for PII. It enumerates every bucket the caller owns, audits each
// one's exposure (public access) and governance (encryption, tagging) to
// surface shadow storage, then samples the flagged buckets for PII using the
// zafrem/pii-pattern-engine rules — with the same cost warnings, rate limiting,
// and resumable session ledger as grep-cloud-storage.
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

	"github.com/zafrem/pii-utils/dark-data-storage/internal/awsx"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/cost"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/discovery"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/engine"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/ner"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/provider"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/report"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/scanner"
	"github.com/zafrem/pii-utils/dark-data-storage/internal/session"
)

type options struct {
	region       string
	patternsDir  string
	locations    string
	categories   string
	filter       string
	discoverOnly bool
	allBuckets   bool
	minTier      string
	sample       int64
	auditList    int
	maxObjectMB  int64
	scanCapKB    int64
	rps          float64
	burst        int
	concurrency  int
	scanBinary   bool
	extractDocs  bool
	assumeYes    bool
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
	fs := flag.NewFlagSet("dark-data-storage", flag.ContinueOnError)
	fs.StringVar(&o.region, "region", "", "AWS region for the API client (default: from environment/profile)")
	fs.StringVar(&o.patternsDir, "patterns", "", "path to pii-pattern-engine/regex (default: auto-detect submodule)")
	fs.StringVar(&o.locations, "locations", "", "comma-separated pattern namespaces to include (e.g. comm,kr,us)")
	fs.StringVar(&o.categories, "categories", "", "comma-separated categories to include (e.g. credit_card,email)")
	fs.StringVar(&o.filter, "filter", "", "only consider buckets whose name contains this substring")
	fs.BoolVar(&o.discoverOnly, "discover-only", false, "audit and report the dark-data surface, then exit without scanning")
	fs.BoolVar(&o.allBuckets, "all-buckets", false, "scan every discovered bucket, not just the flagged (ungoverned) ones")
	fs.StringVar(&o.minTier, "min-tier", "", "only scan buckets at or above this risk tier (low|medium|high|critical)")
	fs.Int64Var(&o.sample, "sample", 500, "max objects to scan per bucket (0 = all)")
	fs.IntVar(&o.auditList, "audit-list", 1000, "objects to LIST per bucket during discovery for an approximate count (0 = skip)")
	fs.Int64Var(&o.maxObjectMB, "max-object-mb", 100, "skip objects larger than this many MB (0 = no limit)")
	fs.Int64Var(&o.scanCapKB, "scan-cap-kb", 0, "read at most this many KB per object (0 = whole object)")
	fs.Float64Var(&o.rps, "rps", 20, "max S3 API requests per second (0 = unlimited)")
	fs.IntVar(&o.burst, "burst", 5, "rate limiter burst size")
	fs.IntVar(&o.concurrency, "concurrency", 8, "number of concurrent object downloads")
	fs.BoolVar(&o.scanBinary, "scan-binary", false, "also scan objects that look binary")
	fs.BoolVar(&o.extractDocs, "extract-docs", true, "extract and scan text from PDF and office (.docx/.xlsx/.pptx) documents")
	fs.BoolVar(&o.assumeYes, "yes", false, "proceed past the cost warning without prompting")
	fs.StringVar(&o.jsonOut, "json", "", "also write a copy of the summary to this file")
	fs.StringVar(&o.out, "out", "", "session directory for the resumable ledger (default: auto-derived)")
	fs.BoolVar(&o.fresh, "fresh", false, "ignore any prior progress in the session dir and start over (existing files archived)")
	fs.BoolVar(&o.ner, "ner", false, "enable the privyscope NER stage (requires the sidecar; see privyscope-ner-server/)")
	fs.StringVar(&o.nerEndpoint, "ner-endpoint", "http://127.0.0.1:8080", "base URL of the privyscope NER sidecar")
	fs.Int64Var(&o.nerMaxKB, "ner-max-kb", 256, "cap text (KB) sent to NER per object (0 = whole object)")
	fs.IntVar(&o.maxAttempts, "max-retries", 10, "max SDK retry attempts per request (adaptive backoff)")
	fs.Int64Var(&o.thObjects, "warn-objects", cost.DefaultThresholds.Objects, "warn when object count reaches this (0 = off)")
	fs.Float64Var(&o.thGB, "warn-gb", cost.DefaultThresholds.GB, "warn when data volume reaches this many GB (0 = off)")
	fs.Float64Var(&o.thUSD, "warn-usd", cost.DefaultThresholds.USD, "warn when estimated cost reaches this many USD (0 = off)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dark-data-storage [flags]\n\n"+
			"Discovers ungoverned cloud storage in the calling account and scans the\n"+
			"flagged buckets for PII. Use --discover-only for an audit without scanning.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if args := fs.Args(); len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v (this tool discovers buckets automatically; use --filter to narrow)", args)
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

	// NER sidecar (optional) — preflight before any AWS calls so a missing
	// sidecar fails fast.
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

	// 3. Discovery — enumerate and audit every bucket the caller owns.
	fmt.Println("Discovering buckets ...")
	facts, err := clients.DiscoverBuckets(ctx, o.auditList)
	if err != nil {
		return err
	}
	if o.filter != "" {
		facts = filterFacts(facts, o.filter)
	}
	assessments := discovery.AssessAll(facts)
	fmt.Print(discovery.Summary(assessments))
	if len(assessments) == 0 {
		fmt.Println("No buckets discovered (or none matched --filter).")
		return nil
	}

	// 5. Open (or resume) the durable session so the discovery report and the
	// scan ledger share one directory.
	meta := session.Meta{
		Bucket:     "discovery-" + caller.Account,
		Prefix:     selectionTag(o),
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
	sess.Report().SameAccount = "yes" // discovery only enumerates the caller's own account
	if err := writeDiscovery(sess.Dir(), assessments); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write discovery report: %v\n", err)
	}
	fmt.Printf("Session: %s (discovery report: %s)\n", sess.Dir(), filepath.Join(sess.Dir(), "discovery.json"))

	if o.discoverOnly {
		fmt.Println("--discover-only: audit written, no objects scanned.")
		return nil
	}

	// 6. Select which buckets to scan.
	selected := discovery.Select(assessments, discovery.Selection{All: o.allBuckets, MinTier: o.minTier})
	if len(selected) == 0 {
		fmt.Println("No buckets selected for scanning (all governed, or none met --min-tier).")
		fmt.Println("Re-run with --all-buckets to scan everything.")
		return nil
	}
	fmt.Printf("Selected %d bucket(s) to scan for PII:\n", len(selected))
	for _, a := range selected {
		fmt.Printf("  • %s [%s] %s\n", a.Name, a.Tier, strings.Join(a.Reasons, "; "))
	}

	// 7. Inventory the selected buckets, skipping objects already recorded on a
	// prior run (resume). Keys in the shared ledger are namespaced "bucket/key".
	type bucketWork struct {
		bucket  string
		region  string
		objects []scanner.Object
	}
	var work []bucketWork
	var totalRemaining int
	var remainingBytes, listRequests int64
	for _, a := range selected {
		sc := newScanner(clients, a, o, nerAnalyzer)
		objs, inv, skippedLarge, ierr := sc.Inventory(ctx)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: inventory failed: %v\n", a.Name, ierr)
			continue
		}
		listRequests += inv.ListRequests
		remaining := objs[:0:0]
		for _, obj := range objs {
			if resumed && sess.Done(ledgerKey(a.Name, obj.Key)) {
				continue
			}
			remaining = append(remaining, obj)
			remainingBytes += obj.Size
		}
		fmt.Printf("  %s: %d objects (%d over size limit, %d already done)\n",
			a.Name, inv.Objects, skippedLarge, len(objs)-len(remaining))
		if len(remaining) > 0 {
			work = append(work, bucketWork{bucket: a.Name, region: a.Region, objects: remaining})
			totalRemaining += len(remaining)
		}
	}
	if totalRemaining == 0 {
		fmt.Println("Nothing to scan (all selected objects already processed).")
		if err := sess.WriteSummary(true, o.jsonOut); err != nil {
			return err
		}
		fmt.Print(sess.Report().Summary())
		return nil
	}

	// 8. Cost estimate + warning gate on the aggregate remaining work.
	est := cost.ComputeAWS(cost.Inventory{Objects: int64(totalRemaining), Bytes: remainingBytes, ListRequests: listRequests}, true)
	fmt.Println("Estimated cost (remaining, all selected buckets):")
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

	// 9. Scan each selected bucket in turn; append every result to the ledger as
	// it completes. Ctrl-C during any bucket leaves the ledger resumable.
	var processed, findingsSoFar, nerErrors int
	scanErr := error(nil)
	fmt.Printf("Scanning at up to %.0f req/s with %d workers ...\n", o.rps, o.concurrency)
	for _, w := range work {
		if ctx.Err() != nil {
			break
		}
		bucket := w.bucket
		sc := newScanner(clients, discovery.Assessment{BucketFacts: discovery.BucketFacts{Name: bucket, Region: w.region}}, o, nerAnalyzer)
		onResult := func(res scanner.Result) {
			key := ledgerKey(bucket, res.Key)
			rec := report.Record{
				Key:          key,
				Size:         res.Size,
				BytesScanned: res.BytesRead,
				Skipped:      res.Skipped,
				SkipReason:   res.SkipReason,
				Extracted:    res.Extracted,
				Findings:     res.Findings,
				ScannedAt:    time.Now(),
			}
			if res.Err != nil {
				rec.Error = res.Err.Error()
			}
			if werr := sess.Record(rec); werr != nil {
				fmt.Fprintf(os.Stderr, "warning: ledger write failed for %s: %v\n", key, werr)
			}
			processed++
			findingsSoFar += len(res.Findings)
			for _, f := range res.Findings {
				fmt.Printf("  [%-8s] %s → %s (%s, conf %d) line %d\n", f.Severity, key, f.Category, f.PatternID, f.Confidence, f.Line)
			}
			if res.Err != nil {
				fmt.Fprintf(os.Stderr, "  error: %s: %s\n", key, res.Err)
			}
			if res.NERErr != nil {
				nerErrors++
				if nerErrors <= 5 {
					fmt.Fprintf(os.Stderr, "  ner-error: %s: %s\n", key, res.NERErr)
				}
			}
			if processed%100 == 0 || processed == totalRemaining {
				fmt.Fprintf(os.Stderr, "  ...%d/%d processed, %d findings so far\n", processed, totalRemaining, findingsSoFar)
			}
		}
		if err := sc.Scan(ctx, w.objects, eng, onResult); err != nil {
			scanErr = err
			if !errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "warning: scan of %s ended: %v\n", bucket, err)
			}
			if ctx.Err() != nil {
				break
			}
		}
	}

	// 10. Finalize.
	complete := ctx.Err() == nil
	if err := sess.WriteSummary(complete, o.jsonOut); err != nil {
		return err
	}
	fmt.Println()
	fmt.Print(sess.Report().Summary())
	if nerErrors > 0 {
		fmt.Printf("  ⚠ NER errors: %d object(s) scanned regex-only (sidecar issue)\n", nerErrors)
	}
	fmt.Printf("  discovery: %s\n  ledger:    %s\n  summary:   %s\n",
		filepath.Join(sess.Dir(), "discovery.json"), filepath.Join(sess.Dir(), "results.jsonl"), sess.SummaryPath())

	if !complete {
		fmt.Printf("\nInterrupted — progress is saved. Resume with the same command:\n  dark-data-storage --out %s\n", sess.Dir())
	}
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		return scanErr
	}
	return nil
}

// newScanner builds a scanner bound to a bucket's own region. The provider
// (region-pinned S3 client) owns rate limiting.
func newScanner(clients *awsx.Clients, a discovery.Assessment, o options, nerAnalyzer scanner.Analyzer) *scanner.Scanner {
	store := provider.NewS3Store(clients.S3ForRegion(a.Region), o.rps, o.burst)
	return scanner.New(store, scanner.Config{
		Bucket:         a.Name,
		MaxObjectBytes: o.maxObjectMB * 1024 * 1024,
		ScanBytesCap:   o.scanCapKB * 1024,
		MaxObjects:     o.sample,
		Concurrency:    o.concurrency,
		SkipBinary:     !o.scanBinary,
		ExtractDocs:    o.extractDocs,
		NER:            nerAnalyzer,
		NERMaxBytes:    o.nerMaxKB * 1024,
	})
}

func filterFacts(facts []discovery.BucketFacts, sub string) []discovery.BucketFacts {
	var out []discovery.BucketFacts
	for _, f := range facts {
		if strings.Contains(f.Name, sub) {
			out = append(out, f)
		}
	}
	return out
}

func ledgerKey(bucket, key string) string { return bucket + "/" + key }

// selectionTag summarizes the scan-selection knobs so a session fingerprint
// distinguishes, e.g., a flagged-only run from an --all-buckets run.
func selectionTag(o options) string {
	parts := []string{}
	if o.allBuckets {
		parts = append(parts, "all")
	} else {
		parts = append(parts, "flagged")
	}
	if o.minTier != "" {
		parts = append(parts, "min="+o.minTier)
	}
	if o.filter != "" {
		parts = append(parts, "filter="+o.filter)
	}
	return strings.Join(parts, ",")
}

// writeDiscovery persists the audit as discovery.json in the session directory.
func writeDiscovery(dir string, assessments []discovery.Assessment) error {
	return discovery.WriteJSON(filepath.Join(dir, "discovery.json"), assessments)
}

// defaultOutDir derives a deterministic session directory from the account and
// selection so re-running the same command resumes automatically.
func defaultOutDir(meta session.Meta) string {
	return fmt.Sprintf("darkdata-%s-%s", sanitizeSlug(meta.Bucket), meta.Fingerprint())
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
		out = "account"
	}
	return out
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
