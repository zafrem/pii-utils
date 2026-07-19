package engine

import "testing"

func TestMergeDropsOverlappingNER(t *testing.T) {
	regex := []Finding{
		{Source: SourceRegex, Category: "phone", ByteOffset: 10, EndOffset: 23},
	}
	ner := []Finding{
		{Source: SourceNER, Category: "phone", ByteOffset: 10, EndOffset: 23}, // overlaps -> dropped
		{Source: SourceNER, Category: "per", ByteOffset: 0, EndOffset: 9},     // distinct -> kept
	}
	got := Merge(regex, ner)
	if len(got) != 2 {
		t.Fatalf("merged len = %d, want 2 (regex phone + ner per)", len(got))
	}
	var per, phones int
	for _, f := range got {
		if f.Category == "per" && f.Source == SourceNER {
			per++
		}
		if f.Category == "phone" {
			phones++
		}
	}
	if per != 1 {
		t.Errorf("expected the non-overlapping NER PER to be kept")
	}
	if phones != 1 {
		t.Errorf("overlapping phone should collapse to the single regex finding, got %d", phones)
	}
}

func TestMergeNoSecondary(t *testing.T) {
	regex := []Finding{{Source: SourceRegex, ByteOffset: 0, EndOffset: 4}}
	if got := Merge(regex, nil); len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

func TestMergePartialOverlapDropped(t *testing.T) {
	regex := []Finding{{Source: SourceRegex, ByteOffset: 5, EndOffset: 15}}
	ner := []Finding{{Source: SourceNER, ByteOffset: 10, EndOffset: 20}} // partial overlap
	if got := Merge(regex, ner); len(got) != 1 {
		t.Fatalf("partial overlap should be dropped; len = %d, want 1", len(got))
	}
}
