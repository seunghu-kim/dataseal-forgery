package veritas

import (
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"

	"dsfgo/field"
	"dsfgo/matrix"
)

func vmat(f field.Field, r, c int, seed uint64) matrix.Mat {
	m := matrix.New(r, c)
	s := seed*2862933555777941757 + 3037000493
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			s = s*6364136223846793005 + 1442695040888963407
			m.Set(i, j, (s>>11)%f.P())
		}
	}
	return m
}

func repRun(rm RepMatmul, a, b matrix.Mat, dim int) (matrix.Mat, bool) {
	n, ell := a.Rows(), b.Cols()
	in := rm.ClientEncrypt(a, dim)
	prog := rm.PrepareProgram(b, n, ell, dim)
	ct := rm.ServerEval(in.Ct, prog)
	verif := rm.VerifierTags(in.Verif, prog)
	return rm.DecodeVerify(ct, verif, prog)
}

// REP authenticated public-right matmul must produce the exact F_p product and
// be accepted by the official vche_1 verifier across sizes that fit nslots.
func TestRepMatmulAuthenticated(t *testing.T) {
	f := field.New(65537)
	dim := 16
	cases := []struct{ n, inner, ell int }{
		{2, 2, 2}, {4, 4, 4}, {8, 8, 8}, {16, 16, 16}, {6, 10, 5},
	}
	for _, tc := range cases {
		rm := NewRepMatmul(bfv.PN13QP218, 4, RotationsFor(tc.inner, tc.ell))
		a := vmat(f, tc.n, tc.inner, 3)
		b := vmat(f, tc.inner, tc.ell, 4)
		want := matrix.Mul(f, a, b)
		got, ok := repRun(rm, a, b, dim)
		if !ok {
			t.Fatalf("REP matmul %+v: official verifier rejected a correct run", tc)
		}
		if !got.Equal(want) {
			t.Fatalf("REP matmul %+v: value mismatch", tc)
		}
	}
}

// Server evaluation must never require the verification poly or secret key: the
// ServerEval signature takes only the ciphertext and the public program.
func TestRepServerOnlyInputs(t *testing.T) {
	f := field.New(65537)
	rm := NewRepMatmul(bfv.PN13QP218, 4, RotationsFor(4, 4))
	a := vmat(f, 4, 4, 1)
	b := vmat(f, 4, 4, 2)
	in := rm.ClientEncrypt(a, 8)
	prog := rm.PrepareProgram(b, 4, 4, 8)
	ct := rm.ServerEval(in.Ct, prog) // compiles with ct + public program only
	verif := rm.VerifierTags(in.Verif, prog)
	got, ok := rm.DecodeVerify(ct, verif, prog)
	if !ok || !got.Equal(matrix.Mul(f, a, b)) {
		t.Fatal("phase-separated REP run failed")
	}
	if prog.Ops().MulPt == 0 || prog.Ops().Rotate == 0 {
		t.Fatalf("unexpected zero program ops: %+v", prog.Ops())
	}
}

func TestRepMatmulSpecialB(t *testing.T) {
	f := field.New(65537)
	dim := 8
	n, inner, ell := 4, 4, 4
	a := vmat(f, n, inner, 9)
	ident := matrix.New(inner, ell)
	for i := 0; i < inner && i < ell; i++ {
		ident.Set(i, i, 1)
	}
	rm := NewRepMatmul(bfv.PN13QP218, 4, RotationsFor(inner, ell))
	got, ok := repRun(rm, a, ident, dim)
	if !ok || !got.Equal(matrix.Mul(f, a, ident)) {
		t.Fatal("REP matmul identity B failed")
	}
}

func peRun(pm PeMatmul, a, b matrix.Mat, dim int) (matrix.Mat, bool) {
	n, ell := a.Rows(), b.Cols()
	in := pm.ClientEncrypt(a, dim)
	prog := pm.PrepareProgram(b, n, ell, dim)
	ct := pm.ServerEval(in.Ct, prog)
	verif := pm.VerifierTags(in.Verif, prog)
	return pm.DecodeVerify(ct, verif, prog)
}

func TestPeMatmulAuthenticated(t *testing.T) {
	f := field.New(65537)
	dim := 8
	cases := []struct{ n, inner, ell int }{
		{2, 2, 2}, {4, 4, 4}, {8, 8, 8}, {5, 6, 4},
	}
	for _, tc := range cases {
		pm := NewPeMatmul(bfv.PN13QP218, RotationsFor(tc.inner, tc.ell))
		if dim*dim > pm.NSlots/2 {
			t.Skipf("PE nslots %d too small for dim %d", pm.NSlots, dim)
		}
		a := vmat(f, tc.n, tc.inner, 7)
		b := vmat(f, tc.inner, tc.ell, 8)
		want := matrix.Mul(f, a, b)
		got, ok := peRun(pm, a, b, dim)
		if !ok {
			t.Fatalf("PE matmul %+v: official verifier rejected a correct run", tc)
		}
		if !got.Equal(want) {
			t.Fatalf("PE matmul %+v: value mismatch", tc)
		}
	}
}

// The official verifier must reject when the result ciphertext and the
// verification tag polynomial disagree. The server circuit runs honestly, but
// the tag polynomial is given an extra evolution the ciphertext never underwent.
// DecodeVerify must surface rejection as accepted=false and must not dereference
// a nil decoded vector (returns a zero matrix of the declared shape).
func TestRepMatmulRejectsMismatch(t *testing.T) {
	f := field.New(65537)
	dim := 8
	n, inner, ell := 4, 4, 4
	rm := NewRepMatmul(bfv.PN13QP218, 4, RotationsFor(inner, ell))
	a := vmat(f, n, inner, 1)
	b := vmat(f, inner, ell, 2)
	in := rm.ClientEncrypt(a, dim)
	prog := rm.PrepareProgram(b, n, ell, dim)
	ct := rm.ServerEval(in.Ct, prog)
	verif := rm.VerifierTags(in.Verif, prog)
	if _, ok := rm.DecodeVerify(ct, verif, prog); !ok {
		t.Fatal("honest run should verify")
	}
	tampered := rm.evaluatorPt.RotateColumnsNew(verif, 1)
	out, ok := rm.DecodeVerify(ct, tampered, prog)
	if ok {
		t.Fatal("verifier accepted a ciphertext/tag mismatch")
	}
	if out.Rows() != n || out.Cols() != ell {
		t.Fatal("rejection must still return a shaped (zero) matrix, no nil deref")
	}
}

func TestPeMatmulRejectsMismatch(t *testing.T) {
	f := field.New(65537)
	dim := 8
	n, inner, ell := 4, 4, 4
	pm := NewPeMatmul(bfv.PN13QP218, RotationsFor(inner, ell))
	a := vmat(f, n, inner, 1)
	b := vmat(f, inner, ell, 2)
	in := pm.ClientEncrypt(a, dim)
	prog := pm.PrepareProgram(b, n, ell, dim)
	ct := pm.ServerEval(in.Ct, prog)
	verif := pm.VerifierTags(in.Verif, prog)
	if _, ok := pm.DecodeVerify(ct, verif, prog); !ok {
		t.Fatal("honest PE run should verify")
	}
	tampered := pm.evaluatorPt.RotateColumnsNew(verif, 1)
	out, ok := pm.DecodeVerify(ct, tampered, prog)
	if ok {
		t.Fatal("PE verifier accepted a ciphertext/tag mismatch")
	}
	if out.Rows() != n || out.Cols() != ell {
		t.Fatal("rejection must still return a shaped (zero) matrix, no nil deref")
	}
}
