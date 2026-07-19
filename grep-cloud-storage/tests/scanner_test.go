package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/engine"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/provider"
	"github.com/zafrem/pii-utils/grep-cloud-storage/internal/scanner"
)

// collect runs a scan and returns results keyed by object key.
func collect(t *testing.T, sc *scanner.Scanner, objs []scanner.Object, eng *engine.Engine) map[string]scanner.Result {
	t.Helper()
	out := map[string]scanner.Result{}
	var mu sync.Mutex
	if err := sc.Scan(context.Background(), objs, eng, func(r scanner.Result) {
		mu.Lock()
		out[r.Key] = r
		mu.Unlock()
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

// TestInventorySizeFilterAndCap exercises the LIST accounting against the fake
// store: the size filter, the sampling cap, and per-page ListRequests counting.
func TestInventorySizeFilterAndCap(t *testing.T) {
	mem := provider.NewMemStore()
	mem.PageSize = 2 // force multiple pages
	mem.Put("b", "a.txt", []byte("small"))
	mem.Put("b", "big.bin", make([]byte, 2000))
	mem.Put("b", "c.txt", []byte("also small"))
	mem.Put("b", "d.txt", []byte("more"))

	sc := scanner.New(mem, scanner.Config{Bucket: "b", MaxObjectBytes: 1000})
	objs, inv, skippedLarge, err := sc.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if skippedLarge != 1 {
		t.Errorf("skippedLarge = %d, want 1 (big.bin over 1000 bytes)", skippedLarge)
	}
	if inv.Objects != 3 || len(objs) != 3 {
		t.Errorf("kept %d objects (inv %d), want 3", len(objs), inv.Objects)
	}
	if inv.ListRequests != 2 {
		t.Errorf("ListRequests = %d, want 2 (4 objects, page size 2)", inv.ListRequests)
	}

	// MaxObjects caps the inventory and stops listing early.
	sc = scanner.New(mem, scanner.Config{Bucket: "b", MaxObjects: 2})
	objs, inv, _, err = sc.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory (capped): %v", err)
	}
	if int64(len(objs)) != 2 || inv.Objects != 2 {
		t.Errorf("capped inventory kept %d, want 2", len(objs))
	}
	if inv.ListRequests != 1 {
		t.Errorf("capped ListRequests = %d, want 1 (stopped after first page)", inv.ListRequests)
	}
}

// TestScanPipelineOverFakeStore verifies the full download+scan path — a PII hit,
// a binary skip, and the byte cap — without touching AWS.
func TestScanPipelineOverFakeStore(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	mem := provider.NewMemStore()
	mem.Put("b", "hit.txt", []byte("customer card 4111111111111111 on file"))
	mem.Put("b", "blob.bin", append([]byte("PK\x00\x00"), make([]byte, 10)...)) // NUL => binary
	mem.Put("b", "capped.txt", []byte("xxxxxxxxxxxxxxxxxxxxxxxx 4111111111111111"))

	sc := scanner.New(mem, scanner.Config{Bucket: "b", SkipBinary: true, ScanBytesCap: 8})
	objs, _, _, err := sc.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	res := collect(t, sc, objs, eng)

	// hit.txt: the card is within the first 8 bytes? No — cap applies to all.
	// With an 8-byte cap the card is beyond the read window, so assert the cap
	// is enforced (BytesRead) rather than a specific finding here.
	if r := res["hit.txt"]; r.BytesRead != 8 {
		t.Errorf("hit.txt BytesRead = %d, want 8 (ScanBytesCap)", r.BytesRead)
	}
	if r := res["blob.bin"]; !r.Skipped || r.SkipReason != "binary content" {
		t.Errorf("blob.bin should be skipped as binary, got skipped=%v reason=%q", r.Skipped, r.SkipReason)
	}

	// Now without a cap: the card is detected and never leaked in the clear.
	sc = scanner.New(mem, scanner.Config{Bucket: "b", SkipBinary: true})
	objs, _, _, _ = sc.Inventory(context.Background())
	res = collect(t, sc, objs, eng)
	hit := res["hit.txt"]
	if !hasCategory(hit.Findings, "credit_card") {
		t.Fatalf("expected a credit_card finding in hit.txt, got %+v", hit.Findings)
	}
	for _, f := range hit.Findings {
		if strings.Contains(f.Masked, "4111111111111111") {
			t.Error("raw card value leaked into masked output")
		}
	}
}

// TestScanRecordsOpenError confirms a per-object Open failure is reported on that
// object's Result without aborting the rest of the scan.
func TestScanRecordsOpenError(t *testing.T) {
	eng, err := engine.Load(regexDir(t), engine.Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	mem := provider.NewMemStore()
	mem.Put("b", "ok.txt", []byte("nothing sensitive"))
	mem.Put("b", "bad.txt", []byte("unused"))
	mem.OpenErr["bad.txt"] = errors.New("access denied")

	sc := scanner.New(mem, scanner.Config{Bucket: "b"})
	objs, _, _, _ := sc.Inventory(context.Background())
	res := collect(t, sc, objs, eng)

	if res["bad.txt"].Err == nil {
		t.Error("bad.txt should carry an Open error")
	}
	if res["ok.txt"].Err != nil {
		t.Errorf("ok.txt should have scanned cleanly, got err %v", res["ok.txt"].Err)
	}
}
