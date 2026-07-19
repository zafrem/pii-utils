package engine

// Merge combines primary findings (regex) with secondary findings (NER),
// dropping any secondary finding whose byte range overlaps a primary one. The
// rationale: a regex hit carries a specific pattern id, checksum verification,
// and a calibrated score, so where both detectors fire on the same span the
// regex finding is the more informative one. Non-overlapping NER findings —
// names, addresses, and other context entities regex misses — are additive.
func Merge(primary, secondary []Finding) []Finding {
	if len(secondary) == 0 {
		return primary
	}
	out := make([]Finding, 0, len(primary)+len(secondary))
	out = append(out, primary...)
	for _, s := range secondary {
		if overlapsAny(s, primary) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func overlapsAny(f Finding, others []Finding) bool {
	for _, o := range others {
		// half-open intervals [ByteOffset, EndOffset) intersect
		if f.ByteOffset < o.EndOffset && o.ByteOffset < f.EndOffset {
			return true
		}
	}
	return false
}
