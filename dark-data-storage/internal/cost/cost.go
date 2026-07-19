// Package cost produces an approximate S3 spend estimate for a scan and decides
// whether the volume warrants a warning before any objects are downloaded.
package cost

import "fmt"

// Pricing in USD. These are standard-tier us-east-1 list prices and are only
// approximate; actual cost varies by region, storage class, and whether the
// caller runs inside AWS. They are intentionally conservative (upper bound).
const (
	getPer1000    = 0.0004 // GET/HEAD requests
	listPer1000   = 0.005  // LIST requests
	egressPerGB   = 0.09   // data transfer OUT to the internet (first tier)
	crossRegionGB = 0.02   // inter-region transfer
	bytesPerGB    = 1 << 30
)

// Inventory is the pre-scan tally gathered from the LIST pass.
type Inventory struct {
	Objects      int64 // objects that will be downloaded and scanned
	Bytes        int64 // total bytes of those objects
	ListRequests int64 // LIST API calls made to build the inventory
}

// Estimate is the computed spend and the inputs behind it.
type Estimate struct {
	GetRequests    int64
	ListRequests   int64
	DataGB         float64
	RequestCostUSD float64
	EgressCostUSD  float64 // upper bound; zero when transfer is expected to be free
	TotalUSD       float64
	EgressCharged  bool
	Note           string
}

// Calculator computes a cloud-specific spend estimate.
type Calculator interface {
	Estimate(inv Inventory, sameAccount bool) Estimate
}

// ComputeAWS estimates S3 cost. When sameAccount is true we assume the scan runs
// inside AWS in the bucket's region, where transfer is free, so only request
// cost is charged. Otherwise we include an internet-egress upper bound.
func ComputeAWS(inv Inventory, sameAccount bool) Estimate {
	dataGB := float64(inv.Bytes) / bytesPerGB
	reqCost := float64(inv.Objects)/1000*getPer1000 + float64(inv.ListRequests)/1000*listPer1000

	e := Estimate{
		GetRequests:    inv.Objects,
		ListRequests:   inv.ListRequests,
		DataGB:         dataGB,
		RequestCostUSD: reqCost,
	}
	if sameAccount {
		e.Note = "same-account scan: assuming in-region execution, data transfer is free (request cost only)"
	} else {
		e.EgressCharged = true
		e.EgressCostUSD = dataGB * egressPerGB
		e.Note = "cross-account/unknown location: including an internet-egress upper bound for data transfer"
	}
	e.TotalUSD = e.RequestCostUSD + e.EgressCostUSD
	return e
}

// Thresholds define when a scan is considered large enough to warn about.
type Thresholds struct {
	Objects int64
	GB      float64
	USD     float64
}

// DefaultThresholds are used when the user does not override them.
var DefaultThresholds = Thresholds{Objects: 100_000, GB: 50, USD: 10}

// ExceedsAny reports whether the estimate trips any threshold, with reasons.
func (e Estimate) ExceedsAny(t Thresholds) (bool, []string) {
	var reasons []string
	if t.Objects > 0 && e.GetRequests >= t.Objects {
		reasons = append(reasons, fmt.Sprintf("%d objects ≥ %d", e.GetRequests, t.Objects))
	}
	if t.GB > 0 && e.DataGB >= t.GB {
		reasons = append(reasons, fmt.Sprintf("%.1f GB ≥ %.0f GB", e.DataGB, t.GB))
	}
	if t.USD > 0 && e.TotalUSD >= t.USD {
		reasons = append(reasons, fmt.Sprintf("est. $%.2f ≥ $%.2f", e.TotalUSD, t.USD))
	}
	return len(reasons) > 0, reasons
}

// Summary renders a human-readable one-block cost breakdown.
func (e Estimate) Summary() string {
	s := fmt.Sprintf(
		"  objects (GET): %d\n  LIST requests: %d\n  data:          %.2f GB\n  request cost:  $%.4f\n",
		e.GetRequests, e.ListRequests, e.DataGB, e.RequestCostUSD,
	)
	if e.EgressCharged {
		s += fmt.Sprintf("  egress (max):  $%.4f\n", e.EgressCostUSD)
	}
	s += fmt.Sprintf("  TOTAL (est.):  $%.4f\n  note: %s", e.TotalUSD, e.Note)
	return s
}
