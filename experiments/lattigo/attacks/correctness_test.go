package attacks

import (
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"dsfgo/bfvpack"
	"dsfgo/matrix"
)

func TestDecomposeRotationSumAndFailHard(t *testing.T) {
	gens := []int{-5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7} // honest matmul(8,6) generators
	for _, target := range []int{0, 1, -1, 12, -12, 96, -84, 7, -5} {
		chain, err := DecomposeRotation(target, gens)
		if err != nil {
			t.Fatalf("target %d: unexpected error %v", target, err)
		}
		sum := 0
		for _, g := range chain {
			sum += g
			if !contains(gens, g) {
				t.Fatalf("target %d: chain used non-generator %d", target, g)
			}
		}
		if sum != target {
			t.Fatalf("target %d: chain sums to %d", target, sum)
		}
		if target == 0 && len(chain) != 0 {
			t.Fatalf("target 0 must be empty chain, got %v", chain)
		}
	}
	// fail-hard: no generator of the needed sign, and empty generator set.
	if _, err := DecomposeRotation(10, []int{-1, -2}); err == nil {
		t.Fatal("expected fail-hard when only negative generators reach a positive target")
	}
	if _, err := DecomposeRotation(5, nil); err == nil {
		t.Fatal("expected fail-hard with no generators")
	}
}

// A composed rotation equals the direct rotation, including the longest chain of
// the n=8 kernel attack.
func TestSynthesizedRotationMatchesDirectNoiseN8(t *testing.T) {
	ctx := bfvpack.NewContext()
	// n=8 kernel shape: honest generators of PublicMatmulRotations(8, 6) and the
	// attack's target offsets n*Dim, -i*Dim, and 1.
	gens := bfvpack.PublicMatmulRotations(8, 6)
	dim := 12
	targets := []int{1, 8 * dim} // 96
	for i := 1; i < 8; i++ {
		targets = append(targets, -i*dim) // -12,-24,...,-84
	}

	// One key set holds generators and targets so both paths decrypt; the composed
	// path uses only gens.
	all := append(append([]int{}, gens...), targets...)
	k := ctx.KeyGen(bfvpack.Capability{Relin: false, Rotations: all})

	// LogicalCols == Dim, so the Decrypt padding region is empty and values moved
	// across slots can be read back.
	const side = 90
	layout := bfvpack.MakeLayout(side, side, side, side)
	m := matrix.New(side, side)
	for i := 0; i < side; i++ {
		for j := 0; j < side; j++ {
			m.Set(i, j, uint64((i*side+j+1)%65537))
		}
	}
	enc := k.Encrypt(m, layout)

	maxDepth, maxTarget := 0, 0
	for _, target := range targets {
		direct := k.RotateCols(enc, target)
		synth, chain, err := SynthesizedRotation(k, enc, target, gens)
		if err != nil {
			t.Fatalf("target %d: synthesis failed: %v", target, err)
		}
		// Any differing slot, including noise corruption after a long chain, decrypts to nonzero.
		if !allZero(k.Decrypt(k.Sub(direct, synth))) {
			t.Fatalf("target %d: synthesized rotation differs from direct (chain depth %d)", target, len(chain))
		}
		if len(chain) > maxDepth {
			maxDepth, maxTarget = len(chain), target
		}
	}
	// Sanity: the deepest rotation actually moved data (not a trivial identity).
	if allZero(k.Decrypt(k.Sub(k.RotateCols(enc, maxTarget), enc))) {
		t.Fatalf("rotation by %d was a no-op; test would be vacuous", maxTarget)
	}
	t.Logf("n=8 kernel: %d target offsets over %d slots; deepest synthesis chain = %d steps (target %d); every target decrypts bit-identically to the direct rotation", len(targets), side*side, maxDepth, maxTarget)
}

// A degree-2 product decrypts correctly without relinearization under PN14QP438.
func TestDegree2DecryptsWithoutRelin(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(bfv.PN14QP438)
	if err != nil {
		t.Fatal(err)
	}
	kgen := bfv.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	enc := bfv.NewEncryptor(params, sk)
	dec := bfv.NewDecryptor(params, sk)
	ecd := bfv.NewEncoder(params)
	eval := bfv.NewEvaluator(params, rlwe.EvaluationKey{}) // deliberately no relin key

	n := int(params.N())
	tmod := params.T()
	a := make([]uint64, n)
	b := make([]uint64, n)
	for i := 0; i < n; i++ {
		a[i] = uint64((i*7 + 1)) % tmod
		b[i] = uint64((i*13 + 3)) % tmod
	}
	pa := bfv.NewPlaintext(params)
	pb := bfv.NewPlaintext(params)
	ecd.EncodeUint(a, pa)
	ecd.EncodeUint(b, pb)

	prod := eval.MulNew(enc.EncryptNew(pa), enc.EncryptNew(pb)) // degree 2, not relinearized
	if prod.Degree() != 2 {
		t.Fatalf("expected a degree-2 ciphertext before relin, got degree %d", prod.Degree())
	}
	out := make([]uint64, n)
	ecd.DecodeUint(dec.DecryptNew(prod), out)

	mismatch := 0
	for i := 0; i < n; i++ {
		if out[i] != (a[i]*b[i])%tmod {
			mismatch++
		}
	}
	if mismatch != 0 {
		t.Fatalf("degree-2 decryption wrong in %d/%d slots", mismatch, n)
	}
	t.Logf("PN14QP438: ct*ct without relin stays degree 2 and decrypts %d/%d slots correctly (relin not needed for decryption)", n-mismatch, n)
}

func allZero(m matrix.Mat) bool {
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			if m.At(i, j) != 0 {
				return false
			}
		}
	}
	return true
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
