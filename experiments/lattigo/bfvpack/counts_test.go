package bfvpack

import (
	"testing"
)

// Operation counts must be a per-single-evaluation quantity: resetting then
// evaluating once always yields the same counts regardless of how many times
// the benchmark repeats the timed call, and repeating without reset scales
// linearly. This guards the F1 counter bug (aggregated counts over trials).
func TestServerOpCountPerInvocation(t *testing.T) {
	ctx := NewContext()
	f := ctx.Field()
	n, d, ell, dim := 16, 16, 16, 16
	a := randMat(f, n, d, 1)
	b := randMat(f, d, ell, 2)
	k := ctx.KeyGen(Capability{Rotations: PublicMatmulRotations(d, ell)})
	ea := k.Encrypt(a, MakeLayout(n, d, n, dim))
	prep := k.PrepareMatmul(ea.Layout, b, ell)

	k.ResetCount()
	k.ServerMatmul(ea, prep)
	one := k.CountSnapshot()

	k.ResetCount()
	k.ServerMatmul(ea, prep)
	two := k.CountSnapshot()
	if one != two {
		t.Fatalf("reset-then-one-eval not stable: %+v vs %+v", one, two)
	}

	// Three repeated evaluations without reset must be exactly 3x (aggregation
	// is linear), proving the earlier 360-vs-30 inflation was trial budget.
	k.ResetCount()
	for i := 0; i < 3; i++ {
		k.ServerMatmul(ea, prep)
	}
	three := k.CountSnapshot()
	if three.Rotate != 3*one.Rotate || three.MulPt != 3*one.MulPt || three.Add != 3*one.Add {
		t.Fatalf("aggregation not linear: 1x=%+v 3x=%+v", one, three)
	}
	// 16x16 single-ct: one rotation per nonzero off-diagonal delta.
	if one.Rotate == 0 || one.MulPt == 0 {
		t.Fatalf("unexpected zero per-eval counts: %+v", one)
	}
	t.Logf("per-eval 16x16: rot=%d mulpt=%d add=%d mulct=%d", one.Rotate, one.MulPt, one.Add, one.MulCt)
}
