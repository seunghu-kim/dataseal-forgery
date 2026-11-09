package bfvpack

import "testing"

func TestPlanSingleCtBoundaries(t *testing.T) {
	// n=64 DataSeal (2 checksum rows): dim 66, 4356 slots -> fits one PN14 half.
	p := PlanMatmul("dataseal", 64, 64, 64, 2, 64, "PN14QP438")
	if p.Strategy != StrategySingleCt {
		t.Fatalf("n=64 dataseal expected single_ct, got %s (%s)", p.Strategy, p.Reason)
	}
	if p.SingleCtDim != 66 || p.SingleCtSlots != 66*66 {
		t.Fatalf("unexpected single-ct dims: %+v", p)
	}

	// n=128 bfv_only: dim 128, 16384 slots -> exceeds PN14 half (8192) -> tiled.
	p = PlanMatmul("bfv_only", 128, 128, 128, 0, 64, "PN14QP438")
	if p.Strategy != StrategyTiled {
		t.Fatalf("n=128 bfv_only expected tiled at PN14, got %s (%s)", p.Strategy, p.Reason)
	}
	if p.IBlocks != 2 || p.KBlocks != 2 || p.JBlocks != 2 || p.TileMultiplies != 8 {
		t.Fatalf("unexpected tile grid: %+v", p)
	}
	// Single-ct would need PN15 for bfv_only 128 (16384 slots == PN15 half).
	if p.SingleCtParam != "PN15QP880" {
		t.Fatalf("n=128 bfv_only single-ct should need PN15, got %q", p.SingleCtParam)
	}

	// n=128 DataSeal: dim 130, 16900 slots -> exceeds even PN15 half -> no single
	// ciphertext anywhere in the registry; tiled is the feasible strategy.
	p = PlanMatmul("dataseal", 128, 128, 128, 2, 64, "PN14QP438")
	if p.SingleCtParam != "" {
		t.Fatalf("n=128 dataseal single-ct should be infeasible in registry, got %q", p.SingleCtParam)
	}
	if p.Strategy != StrategyTiled {
		t.Fatalf("n=128 dataseal expected tiled, got %s", p.Strategy)
	}
	if p.IBlocks != 3 { // 130 rows / 64 -> 3 block rows (64,64,2)
		t.Fatalf("n=128 dataseal expected 3 block rows, got %d", p.IBlocks)
	}
}

func TestPlanDeterministic(t *testing.T) {
	a := PlanMatmul("dataseal", 128, 128, 128, 2, 64, "PN14QP438")
	b := PlanMatmul("dataseal", 128, 128, 128, 2, 64, "PN14QP438")
	if a != b {
		t.Fatal("planner is not deterministic")
	}
}
