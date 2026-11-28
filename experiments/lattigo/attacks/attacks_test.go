package attacks

import (
	"testing"

	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
)

type Attempt struct {
	Accepted, Wrong, Unchanged bool
}

func (a Attempt) Forged() bool { return a.Accepted && a.Wrong }

func judge(accepted bool, returnedFull, honestFull, returnedData, correctData matrix.Mat) Attempt {
	return Attempt{
		Accepted:  accepted,
		Wrong:     !returnedData.Equal(correctData),
		Unchanged: returnedFull.Equal(honestFull),
	}
}

var N = 3
var D = 5

func fixture() (bfvpack.Context, field.Field, matrix.Mat, matrix.Mat, []uint64) {
	c := bfvpack.NewContext()
	f := c.Field()
	a := matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
	b := matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}})
	k := f.VecFromInts([]int64{2, 3, 5})
	return c, f, a, b, k
}

func kernelRots(n, dim int, ch KernelChoice) []int {
	set := map[int]bool{
		ch.ColA - ch.Target: true, ch.ColB - ch.Target: true,
		n * dim: true,
	}
	for _, col := range []int{ch.ColA, ch.ColB} {
		set[col-ch.Target] = true
	}
	for i := 1; i < n; i++ {
		set[-i*dim] = true
	}
	delete(set, 0)
	out := []int{}
	for x := range set {
		out = append(out, x)
	}
	return out
}

func TestKernelForgesCorrectedMatmul(t *testing.T) {
	c, f, a, b, kvec := fixture()
	e := dataseal.MatmulEncode(f, a, b, dataseal.MatmulKey{K: kvec, Alpha: 7})
	ch := KernelChoice{0, 1, 0}
	rots := append(bfvpack.PublicMatmulRotations(2, 2), kernelRots(N, D, ch)...)
	keys := c.KeyGen(bfvpack.Capability{Relin: true, Rotations: rots})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(N+2, 2, N, D))
	honest := keys.PublicRightMatmul(in, b, 2)
	changed := KernelAdjustedOutput(keys, in, honest, N, ch)
	c0 := keys.Decrypt(honest)
	c1 := keys.Decrypt(changed)
	correct := matrix.Mul(f, a, b)
	for _, mode := range []dataseal.MatmulVerifier{dataseal.Original, dataseal.Corrected, dataseal.Appendix} {
		at := judge(dataseal.MatmulVerify(f, e.Client, c1, mode).Accepted(), c1, c0, c1.TopRows(N), correct)
		if !at.Forged() {
			t.Fatalf("verifier %v not forged: accepted=%v wrong=%v", mode, at.Accepted, at.Wrong)
		}
	}
}

func TestSelectiveScalingOriginalOnly(t *testing.T) {
	c, f, a, b, kvec := fixture()
	e := dataseal.MatmulEncode(f, a, b, dataseal.MatmulKey{K: kvec, Alpha: 7})
	keys := c.KeyGen(bfvpack.Capability{Rotations: bfvpack.PublicMatmulRotations(2, 2)})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(N+2, 2, N, D))
	honest := keys.PublicRightMatmul(in, b, 2)
	changed := SelectiveScaling(keys, f, honest, N, 3)
	c0 := keys.Decrypt(honest)
	c1 := keys.Decrypt(changed)
	correct := matrix.Mul(f, a, b)
	orig := judge(dataseal.MatmulVerify(f, e.Client, c1, dataseal.Original).Accepted(), c1, c0, c1.TopRows(N), correct)
	strong := judge(dataseal.MatmulVerify(f, e.Client, c1, dataseal.Corrected).Accepted(), c1, c0, c1.TopRows(N), correct)
	if !orig.Forged() {
		t.Fatal("selective scaling should forge original")
	}
	if strong.Accepted {
		t.Fatal("strengthened should reject selective scaling")
	}
}

func TestKernelForgesAddition(t *testing.T) {
	c, f, a, _, kvec := fixture()
	b := matrix.FromInts(f, [][]int64{{4, 1}, {0, 9}, {2, 2}})
	e := dataseal.AddEncode(f, a, b, kvec)
	ch := KernelChoice{0, 1, 1}
	keys := c.KeyGen(bfvpack.Capability{Relin: true, Rotations: kernelRots(N, D, ch)})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(N+1, 2, N, D))
	other := keys.Encrypt(e.BStar, bfvpack.MakeLayout(N+1, 2, N, D))
	honest := keys.Add(in, other)
	changed := KernelAdjustedOutput(keys, in, honest, N, ch)
	c0 := keys.Decrypt(honest)
	c1 := keys.Decrypt(changed)
	at := judge(dataseal.AddVerify(f, e.Client, c1).Accepted(), c1, c0, c1.TopRows(N), matrix.Add(f, a, b))
	if !at.Forged() {
		t.Fatalf("addition kernel not forged: %+v", at)
	}
}

func TestSquarePermuteForges(t *testing.T) {
	c := bfvpack.NewContext()
	f := c.Field()
	a := matrix.FromInts(f, [][]int64{{2, 3}, {4, 5}, {6, 7}})
	e := dataseal.SquareEncode(f, a, f.VecFromInts([]int64{7, 11}))
	keys := c.KeyGen(bfvpack.Capability{Relin: true, Rotations: []int{2 * D, -2 * D}})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(4, 2, 3, D))
	honest := keys.Square(in)
	changed := SquarePermute(keys, honest, 3, 0, 2, 1)
	c0 := keys.Decrypt(honest)
	c1 := keys.Decrypt(changed)
	at := judge(dataseal.SquareVerify(f, e.Client, c1).Accepted(), c1, c0, c1.TopRows(3), matrix.Square(f, a))
	if !at.Forged() {
		t.Fatalf("square permute not forged: %+v", at)
	}
}

func TestSquareRescaleForges(t *testing.T) {
	c := bfvpack.NewContext()
	f := c.Field()
	a := matrix.FromInts(f, [][]int64{{2, 3}, {4, 5}, {6, 7}})
	e := dataseal.SquareEncode(f, a, f.VecFromInts([]int64{7, 11}))
	keys := c.KeyGen(bfvpack.Capability{Relin: true})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(4, 2, 3, D))
	honest := keys.Square(in)
	changed := SquareRescale(keys, f, honest, 1, 0, 2, 3)
	c0 := keys.Decrypt(honest)
	c1 := keys.Decrypt(changed)
	at := judge(dataseal.SquareVerify(f, e.Client, c1).Accepted(), c1, c0, c1.TopRows(3), matrix.Square(f, a))
	if !at.Forged() {
		t.Fatalf("square rescale not forged: %+v", at)
	}
}

func TestMissingCapabilityUnsupported(t *testing.T) {
	c, f, a, b, kvec := fixture()
	e := dataseal.MatmulEncode(f, a, b, dataseal.MatmulKey{K: kvec, Alpha: 7})
	ch := KernelChoice{0, 1, 0}
	// no relin, no rotations: kernel needs both -> Lattigo panics (unsupported).
	keys := c.KeyGen(bfvpack.Capability{})
	in := keys.Encrypt(e.AStar, bfvpack.MakeLayout(N+2, 2, N, D))
	honest := bfvpack.Cipher{}
	_ = honest
	defer func() {
		if recover() == nil {
			t.Fatal("expected UNSUPPORTED_CAPABILITY panic without keys")
		}
	}()
	_ = KernelAdjustedOutput(keys, in, in, N, ch)
}
