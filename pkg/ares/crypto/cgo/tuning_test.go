// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

func TestTuneUnionUsesMaxPairwiseDiffForRangeControl(t *testing.T) {
	_, tuned := TuneUnion(DistributionMetadata{
		MinMargin:       0.1,
		MedianMargin:    0.1,
		MaxMargin:       0.1,
		MaxPairwiseDiff: 1.0,
	}, []UnionComparator{{
		ID:         "narrow",
		Comparator: "logistic",
		Gain:       4,
		Bound:      1,
	}}, 4)

	if got := tuned[0].InputScale; got > 0.03 {
		t.Fatalf("InputScale %.6f ignores max pairwise range; want <= 0.03", got)
	}
}

func TestTuneUnionPreservesPerComparatorRangeMargins(t *testing.T) {
	_, tuned := TuneUnion(DistributionMetadata{
		MinMargin:       0.1,
		MedianMargin:    0.1,
		MaxMargin:       0.1,
		MaxPairwiseDiff: 1.0,
	}, []UnionComparator{
		{ID: "close", Comparator: "logistic", Gain: 4, Bound: 3, RangeMargin: 0.1},
		{ID: "wide", Comparator: "logistic", Gain: 3, Bound: 6, RangeMargin: 1.0},
	}, 4)

	if !(tuned[0].InputScale > tuned[1].InputScale) {
		t.Fatalf("close comparator scale %.6f must exceed wide comparator scale %.6f", tuned[0].InputScale, tuned[1].InputScale)
	}
}

func TestClampUnionConcurrency(t *testing.T) {
	comparators := []UnionComparator{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	if got := clampUnionConcurrency(0, comparators); got != 1 {
		t.Fatalf("clampUnionConcurrency(0) = %d, want 1", got)
	}
	if got := clampUnionConcurrency(5, comparators); got != 3 {
		t.Fatalf("clampUnionConcurrency(5) = %d, want 3", got)
	}
	if got := clampUnionConcurrency(2, comparators); got != 2 {
		t.Fatalf("clampUnionConcurrency(2) = %d, want 2", got)
	}
}

func TestUnionComparatorRequestCanUsePreinsertedEvalKeys(t *testing.T) {
	req := FullFuseRequest{
		EvalKeys: EvalKeyFinal{
			EvalMultFinal: []byte("mult"),
			EvalSumFinal:  []byte("sum"),
		},
	}
	comp := UnionComparator{
		Comparator: "logistic",
		Schedule:   "none",
		Gain:       6,
		Bound:      5,
		InputScale: 0.25,
		Degree:     13,
	}

	got := unionComparatorRequest(req, comp, true)
	if len(got.EvalKeys.EvalMultFinal) != 0 || len(got.EvalKeys.EvalSumFinal) != 0 {
		t.Fatal("preinserted eval-key request should not carry serialized eval keys")
	}
	if got.Comparator != "logistic" || got.SelectorSchedule != "none" || got.ComparatorGain != 6 || got.ComparatorBound != 5 || got.ComparatorScale != 0.25 || got.ComparatorDegree != 13 {
		t.Fatalf("comparator fields not applied: %+v", got)
	}
}
