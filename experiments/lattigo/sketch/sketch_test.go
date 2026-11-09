package sketch

import (
	"testing"

	"dsfgo/field"
	"dsfgo/matrix"
)

var f = field.New(65537)

func TestRowsForBudget(t *testing.T) {
	if RowsFor(65537, 128, 1<<32) != 10 {
		t.Fatal("r should be 10 at 128-bit, q=2^32")
	}
	if RowsFor(65537, 128, 1) != 8 {
		t.Fatal("r should be 8 at q=1")
	}
	if RowsFor(2, 10, 1) != 10 || RowsFor(2, 10, 2) != 11 {
		t.Fatal("binary field rows")
	}
}

func TestHonestComposition(t *testing.T) {
	n := 6
	cs := Keygen(f, RowsFor(65537, 128, 1<<32), n)
	sv := NewServer()
	a := RandomMat(f, n, 4)
	d := RandomMat(f, n, 5)
	Register(f, &cs, &sv, "A", a)
	Register(f, &cs, &sv, "D", d)
	b1 := RandomMat(f, 4, 5)
	b2 := RandomMat(f, 5, 3)
	prog := Program{{Kind: Input, Label: "A"}, {Kind: MulRight, Mat: b1}, {Kind: AddInput, Label: "D"}, {Kind: MulRight, Mat: b2}}
	y := Eval(f, sv, prog)
	want := matrix.Mul(f, matrix.Add(f, matrix.Mul(f, a, b1), d), b2)
	if !y.Equal(want) {
		t.Fatal("composition eval")
	}
	if !Verify(f, cs, Prepare(f, cs, prog), y) {
		t.Fatal("verify honest composition")
	}
}

func TestTwoProgramsOneEncoding(t *testing.T) {
	n := 5
	cs := Keygen(f, 10, n)
	sv := NewServer()
	a := RandomMat(f, n, 4)
	Register(f, &cs, &sv, "A", a)
	p1 := Program{{Kind: Input, Label: "A"}, {Kind: MulRight, Mat: RandomMat(f, 4, 3)}}
	p2 := Program{{Kind: Input, Label: "A"}, {Kind: MulRight, Mat: RandomMat(f, 4, 2)}}
	y1 := Eval(f, sv, p1)
	y2 := Eval(f, sv, p2)
	if !Verify(f, cs, Prepare(f, cs, p1), y1) || !Verify(f, cs, Prepare(f, cs, p2), y2) {
		t.Fatal("verify two programs")
	}
	if Verify(f, cs, Prepare(f, cs, p1), y2) {
		t.Fatal("cross-verify must reject")
	}
}

func TestVerifyRejectsTamperAndScaling(t *testing.T) {
	n := 5
	cs := Keygen(f, 10, n)
	sv := NewServer()
	a := RandomMat(f, n, 4)
	Register(f, &cs, &sv, "A", a)
	prog := Program{{Kind: Input, Label: "A"}, {Kind: MulRight, Mat: RandomMat(f, 4, 3)}}
	y := Eval(f, sv, prog)
	tp := Prepare(f, cs, prog)
	if !Verify(f, cs, tp, y) {
		t.Fatal("honest")
	}
	if Verify(f, cs, tp, matrix.Scale(f, 3, y)) {
		t.Fatal("scaling accepted")
	}
	bad := Eval(f, sv, prog)
	bad.Set(4, 2, f.Add(bad.At(4, 2), 1))
	if Verify(f, cs, tp, bad) {
		t.Fatal("tamper accepted")
	}
}

func TestServerHasNoKeyOrSketch(t *testing.T) {
	cs := Keygen(f, 10, 4)
	sv := NewServer()
	Register(f, &cs, &sv, "A", RandomMat(f, 4, 3))
	if len(sv.Inputs) != 1 {
		t.Fatal("server should hold one input")
	}
	// Server type has no K/W field at all (compile-time guarantee); runtime: only Inputs.
}
