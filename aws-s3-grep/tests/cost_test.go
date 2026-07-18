package tests

import (
	"strings"
	"testing"

	"github.com/zafrem/pii-utils/aws-s3-grep/internal/cost"
)

func TestCostSameAccountHasNoEgress(t *testing.T) {
	inv := cost.Inventory{Objects: 1000, Bytes: 5 << 30, ListRequests: 1}
	est := cost.Compute(inv, true)
	if est.EgressCharged {
		t.Error("same-account scan should not charge egress")
	}
	if est.EgressCostUSD != 0 {
		t.Errorf("egress = %.4f, want 0", est.EgressCostUSD)
	}
	if est.TotalUSD != est.RequestCostUSD {
		t.Errorf("total (%.4f) should equal request cost (%.4f) when transfer is free", est.TotalUSD, est.RequestCostUSD)
	}
}

func TestCostCrossAccountAddsEgress(t *testing.T) {
	inv := cost.Inventory{Objects: 1000, Bytes: 10 << 30, ListRequests: 1}
	est := cost.Compute(inv, false)
	if !est.EgressCharged || est.EgressCostUSD <= 0 {
		t.Fatal("cross-account scan should include an egress upper bound")
	}
	if est.TotalUSD <= est.RequestCostUSD {
		t.Error("total should exceed request cost when egress is charged")
	}
}

func TestCostThresholds(t *testing.T) {
	est := cost.Compute(cost.Inventory{Objects: 200_000, Bytes: 1 << 30, ListRequests: 10}, true)

	exceeds, reasons := est.ExceedsAny(cost.Thresholds{Objects: 100_000})
	if !exceeds || len(reasons) == 0 {
		t.Error("200k objects should trip a 100k object threshold")
	}

	if ex, _ := est.ExceedsAny(cost.Thresholds{Objects: 0, GB: 0, USD: 0}); ex {
		t.Error("all-zero thresholds should never trip")
	}

	if ex, _ := est.ExceedsAny(cost.Thresholds{Objects: 10_000_000}); ex {
		t.Error("200k objects should not trip a 10M threshold")
	}

	if s := est.Summary(); !strings.Contains(s, "TOTAL") {
		t.Errorf("summary should include a TOTAL line, got:\n%s", s)
	}
}
