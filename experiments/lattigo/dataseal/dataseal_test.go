package dataseal

import (
	"testing"

	"dsfgo/field"
	"dsfgo/matrix"
)

var f = field.New(65537)

func TestFieldFixtures(t *testing.T) {
	if f.FromInt(-1) != 65536 || f.FromInt(-65537) != 0 {
		t.Fatal("canonical reduction")
	}
	big := field.New((1 << 61) - 1)
	if big.Mul(big.P()-1, big.P()-1) != 1 {
		t.Fatal("overflow-safe mul")
	}
	if f.Mul(f.FromInt(-5), f.Inv(f.FromInt(-5))) != 1 {
		t.Fatal("inverse")
	}
}

// Kernel fixture: k=(2,3,5), a1=(1,2,0), a2=(0,1,1) -> w1=w2=8, h=(8,8,-8), k^T h=0.
func TestKernelFixtureMath(t *testing.T) {
	k := f.VecFromInts([]int64{2, 3, 5})
	a := matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
	w := matrix.MatTVec(f, a, k)
	if w[0] != 8 || w[1] != 8 {
		t.Fatalf("w=%v", w)
	}
	h := make([]uint64, 3)
	for i := 0; i < 3; i++ {
		h[i] = f.Sub(f.Mul(w[1], a.At(i, 0)), f.Mul(w[0], a.At(i, 1)))
	}
	want := f.VecFromInts([]int64{8, 8, -8})
	for i := range h {
		if h[i] != want[i] {
			t.Fatalf("h=%v want %v", h, want)
		}
	}
	if f.Dot(k, h) != 0 || field.IsZero(h) {
		t.Fatal("k^T h must be 0 and h nonzero")
	}
}

func TestMatmulEncodingLayout(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
	b := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}})
	e := MatmulEncode(f, a, b, MatmulKey{f.VecFromInts([]int64{2, 3, 5}), 7})
	if !eq(e.AStar.Row(3), f.VecFromInts([]int64{8, 8})) {
		t.Fatalf("w row %v", e.AStar.Row(3))
	}
	if !eq(e.AStar.Row(4), f.VecFromInts([]int64{56, 56})) {
		t.Fatalf("g row %v", e.AStar.Row(4))
	}
	if !eq(e.Client.U0, f.VecFromInts([]int64{32, 48})) || !eq(e.Client.Z, f.VecFromInts([]int64{224, 336})) {
		t.Fatalf("u0=%v z=%v", e.Client.U0, e.Client.Z)
	}
}

func TestMatmulHonestAccepted(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
	b := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}})
	e := MatmulEncode(f, a, b, MatmulKey{f.VecFromInts([]int64{2, 3, 5}), 7})
	cStar := MatmulEval(f, e)
	if !cStar.TopRows(3).Equal(matrix.Mul(f, a, b)) {
		t.Fatal("data rows")
	}
	for _, mode := range []MatmulVerifier{Original, Corrected, Appendix} {
		if !MatmulVerify(f, e.Client, cStar, mode).Accepted() {
			t.Fatalf("mode %v rejected honest", mode)
		}
	}
}

func TestMatmulRejectsTamper(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
	b := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}})
	e := MatmulEncode(f, a, b, MatmulKey{f.VecFromInts([]int64{2, 3, 5}), 7})
	cStar := MatmulEval(f, e)
	cStar.Set(0, 0, f.Add(cStar.At(0, 0), 1))
	for _, mode := range []MatmulVerifier{Original, Corrected, Appendix} {
		if MatmulVerify(f, e.Client, cStar, mode).Accepted() {
			t.Fatalf("mode %v accepted tamper", mode)
		}
	}
}

func TestAdditionHonestAndTamper(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}, {5, 6}})
	b := matrix.FromInts(f, [][]int64{{6, 5}, {4, 3}, {2, 1}})
	e := AddEncode(f, a, b, f.VecFromInts([]int64{2, 3, 5}))
	cStar := AddEval(f, e)
	if !cStar.TopRows(3).Equal(matrix.Add(f, a, b)) || !AddVerify(f, e.Client, cStar).Accepted() {
		t.Fatal("honest addition")
	}
	cStar.Set(1, 1, f.Add(cStar.At(1, 1), 1))
	if AddVerify(f, e.Client, cStar).Accepted() {
		t.Fatal("accepted addition tamper")
	}
}

// Square fixture: A=[[1,2],[4,3]], eta=(3,5) -> t=(12,30), z=(144,900).
func TestSquareFixtureAndVerify(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 2}, {4, 3}})
	e := SquareEncode(f, a, f.VecFromInts([]int64{3, 5}))
	if !eq(e.AStar.Row(2), f.VecFromInts([]int64{12, 30})) || !eq(e.Client.Z, f.VecFromInts([]int64{144, 900})) {
		t.Fatalf("t=%v z=%v", e.AStar.Row(2), e.Client.Z)
	}
	cStar := SquareEval(f, e)
	if !cStar.TopRows(2).Equal(matrix.Square(f, a)) || !SquareVerify(f, e.Client, cStar).Accepted() {
		t.Fatal("honest square")
	}
	cStar.Set(0, 1, f.Add(cStar.At(0, 1), 1))
	if SquareVerify(f, e.Client, cStar).Accepted() {
		t.Fatal("accepted square tamper")
	}
}

func TestAppendixDistinctFromOriginal(t *testing.T) {
	a := matrix.FromInts(f, [][]int64{{1, 0, 2}, {2, 1, 1}, {0, 1, 3}, {1, 1, 1}})
	b := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}, {0, 1}})
	e := MatmulEncode(f, a, b, MatmulKey{f.VecFromInts([]int64{1, 2, 3, 4}), 5})
	cStar := MatmulEval(f, e)
	ro := MatmulVerify(f, e.Client, cStar, Original)
	ra := MatmulVerify(f, e.Client, cStar, Appendix)
	if _, ok := ro.Checks["scaled_checksum"]; ok {
		t.Fatal("original must not have appendix check")
	}
	if _, ok := ra.Checks["golden_output"]; ok {
		t.Fatal("appendix must not have golden check")
	}
}
