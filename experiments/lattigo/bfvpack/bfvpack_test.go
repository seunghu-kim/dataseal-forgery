package bfvpack

import (
	"testing"

	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
)

func ctx() Context { return NewContext() }

func rnd(f field.Field, r, c int, seed uint64) matrix.Mat {
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

func TestContextBatching(t *testing.T) {
	c := ctx()
	if c.Field().P() != 65537 || c.Slots() != 16384 || c.RowSlots() != 8192 {
		t.Fatalf("params N=%d t=%d", c.Slots(), c.Field().P())
	}
	if (c.Field().P()-1)%uint64(2*c.Slots()) != 0 {
		t.Fatal("2N must divide t-1")
	}
}

func TestSlotProbeRotation(t *testing.T) {
	c := ctx()
	k := c.KeyGen(Capability{Rotations: []int{1, -1}})
	// one-hot at slot 0 and slot 5 within the first row
	l := MakeLayout(1, 8, 1, 8)
	m := matrix.New(1, 8)
	m.Set(0, 0, 3)
	m.Set(0, 5, 7)
	enc := k.Encrypt(m, l)
	rotated := Cipher{l, k.eval.RotateColumnsNew(enc.ct, 1)}
	out := k.Decrypt(rotated)
	// RotateColumns by 1: slot i gets value from slot i+1, so slot 4 holds 7.
	if out.At(0, 4) != 7 {
		t.Fatalf("rotation semantics unexpected: %v", out.Row(0))
	}
}

func TestEncryptRoundtrip(t *testing.T) {
	c := ctx()
	k := c.KeyGen(Capability{})
	m := matrix.FromInts(c.Field(), [][]int64{{0, 1, 65536}, {2, 3, 4}, {5, 6, 7}})
	l := MakeLayout(3, 3, 3, 5)
	if !k.Decrypt(k.Encrypt(m, l)).Equal(m) {
		t.Fatal("roundtrip")
	}
}

func TestPublicRightMatmulMatchesPlaintext(t *testing.T) {
	c := ctx()
	f := c.Field()
	for _, d := range []int{2, 3, 4} {
		k := c.KeyGen(Capability{Rotations: PublicMatmulRotations(d, d)})
		a := rnd(f, d, d, uint64(d))
		b := rnd(f, d, d, uint64(d+100))
		ea := k.Encrypt(a, MakeLayout(d, d, d, d))
		got := k.Decrypt(k.PublicRightMatmul(ea, b, d))
		if !got.Equal(matrix.Mul(f, a, b)) {
			t.Fatalf("d=%d mismatch", d)
		}
		if k.Count.MulCt != 0 {
			t.Fatal("public matmul must not use ct-ct mult")
		}
	}
}

func TestPublicRightMatmulRectangular(t *testing.T) {
	c := ctx()
	f := c.Field()
	n, d, ell, D := 3, 2, 4, 5
	k := c.KeyGen(Capability{Rotations: PublicMatmulRotations(d, ell)})
	a := rnd(f, n, d, 7)
	b := rnd(f, d, ell, 8)
	ea := k.Encrypt(a, MakeLayout(n, d, n, D))
	got := k.Decrypt(k.PublicRightMatmul(ea, b, ell))
	if !got.Equal(matrix.Mul(f, a, b)) {
		t.Fatal("rectangular mismatch")
	}
}

func TestDataSealMatmulOverBFV(t *testing.T) {
	c := ctx()
	f := c.Field()
	n, d, ell := 4, 3, 2
	D := n + 2
	if d > D {
		D = d
	}
	a := rnd(f, n, d, 11)
	b := rnd(f, d, ell, 12)
	key := dataseal.MatmulKey{K: f.VecFromInts([]int64{2, 3, 5, 7}), Alpha: 9}
	e := dataseal.MatmulEncode(f, a, b, key)
	k := c.KeyGen(Capability{Rotations: PublicMatmulRotations(d, ell)})
	ea := k.Encrypt(e.AStar, MakeLayout(n+2, d, n, D))
	out := k.Decrypt(k.PublicRightMatmul(ea, b, ell))
	if !out.Equal(dataseal.MatmulEval(f, e)) {
		t.Fatal("dataseal matmul over BFV mismatch")
	}
	for _, mode := range []dataseal.MatmulVerifier{dataseal.Original, dataseal.Strengthened, dataseal.Appendix} {
		if !dataseal.MatmulVerify(f, e.Client, out, mode).Accepted() {
			t.Fatalf("verifier %v rejected", mode)
		}
	}
}

func TestDataSealAdditionOverBFV(t *testing.T) {
	c := ctx()
	f := c.Field()
	n, d, D := 4, 3, 5
	a := rnd(f, n, d, 13)
	b := rnd(f, n, d, 14)
	e := dataseal.AddEncode(f, a, b, f.VecFromInts([]int64{2, 3, 5, 7}))
	k := c.KeyGen(Capability{})
	ea := k.Encrypt(e.AStar, MakeLayout(n+1, d, n, D))
	eb := k.Encrypt(e.BStar, MakeLayout(n+1, d, n, D))
	out := k.Decrypt(k.Add(ea, eb))
	if !out.Equal(dataseal.AddEval(f, e)) || !dataseal.AddVerify(f, e.Client, out).Accepted() {
		t.Fatal("dataseal addition over BFV")
	}
}

func TestDataSealSquareOverBFV(t *testing.T) {
	c := ctx()
	f := c.Field()
	n, d, D := 4, 3, 5
	a := rnd(f, n, d, 15)
	e := dataseal.SquareEncode(f, a, f.VecFromInts([]int64{3, 5, 7}))
	k := c.KeyGen(Capability{Relin: true})
	ea := k.Encrypt(e.AStar, MakeLayout(n+1, d, n, D))
	out := k.Decrypt(k.Square(ea))
	if !out.Equal(dataseal.SquareEval(f, e)) || !dataseal.SquareVerify(f, e.Client, out).Accepted() {
		t.Fatal("dataseal square over BFV")
	}
}

func TestPrivateSketchOverBFV(t *testing.T) {
	c := ctx()
	f := c.Field()
	n := 6
	cs := sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n)
	sv := sketch.NewServer()
	a := rnd(f, n, 4, 16)
	d := rnd(f, n, 5, 17)
	sketch.Register(f, &cs, &sv, "A", a)
	sketch.Register(f, &cs, &sv, "D", d)
	b1 := rnd(f, 4, 5, 18)
	b2 := rnd(f, 5, 3, 19)
	D := 8
	k := c.KeyGen(Capability{Rotations: unionRots(PublicMatmulRotations(4, 5), PublicMatmulRotations(5, 3))})
	ea := k.Encrypt(a, MakeLayout(n, 4, n, D))
	ed := k.Encrypt(d, MakeLayout(n, 5, n, D))
	// (A B1 + D) B2
	ab1 := k.PublicRightMatmul(ea, b1, 5)
	sum := k.Add(ab1, ed)
	y := k.Decrypt(k.PublicRightMatmul(sum, b2, 3))
	prog := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b1}, {Kind: sketch.AddInput, Label: "D"}, {Kind: sketch.MulRight, Mat: b2}}
	if !y.Equal(sketch.Eval(f, sv, prog)) {
		t.Fatal("sketch BFV eval mismatch")
	}
	if !sketch.Verify(f, cs, sketch.Prepare(f, cs, prog), y) {
		t.Fatal("sketch BFV verify")
	}
}

func unionRots(a, b []int) []int {
	set := map[int]bool{}
	for _, x := range append(a, b...) {
		set[x] = true
	}
	out := []int{}
	for x := range set {
		out = append(out, x)
	}
	return out
}
