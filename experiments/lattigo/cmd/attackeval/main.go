// Command attackeval re-runs the ciphertext-level DataSeal verification-forgery
// experiments with explicit evaluation-key capability accounting (F4). For each
// adversary transformation it records: the exact evaluation keys distributed,
// the per-transformation operation counts, the honest-function key set, and the
// outcome class. The central question is which forgeries work under the
// *minimal honest* key set versus which require *extended* keys the honest
// public-right-matmul (or squaring) would not distribute.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"dsfgo/attacks"
	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
)

// Outcome classes (F4.4).
const (
	honestCorrect  = "honest_correct"
	acceptedWrong  = "accepted_wrong" // forged
	rejectedWrong  = "rejected_wrong"
	unchanged      = "unchanged"
	unsupportedCap = "unsupported_capability"
	heError        = "he_error"
)

type trial struct {
	Attack     string `json:"attack"`
	Verifier   string `json:"verifier"`
	Capability string `json:"capability_profile"` // honest_minimal | extended
	N          int    `json:"n"`
	D          int    `json:"d"`
	Ell        int    `json:"ell"`
	KeysRelin  bool   `json:"keys_relin"`
	KeysRot    []int  `json:"keys_rotations"`
	Rotate     int    `json:"op_rotate"`
	MulPt      int    `json:"op_mul_pt"`
	MulCt      int    `json:"op_mul_ct"`
	Add        int    `json:"op_add"`
	Outcome    string `json:"outcome"`
	Note       string `json:"note,omitempty"`
}

func classify(accepted bool, honestFull, outFull, outData, correctData matrix.Mat) string {
	wrong := !outData.Equal(correctData)
	if outFull.Equal(honestFull) {
		return unchanged
	}
	if accepted && wrong {
		return acceptedWrong
	}
	if !accepted && wrong {
		return rejectedWrong
	}
	if accepted && !wrong {
		return honestCorrect
	}
	return rejectedWrong
}

func capture(run func() string) (outcome string) {
	defer func() {
		if r := recover(); r != nil {
			outcome = unsupportedCap
		}
	}()
	return run()
}

// matmul fixtures at two sizes with a nonzero-kernel precondition (rank check).
type size struct{ n, d, ell, dim int }

func main() {
	outDir := "../../results/attacks_final"
	if len(os.Args) == 2 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0o755)
	f := field.New(65537)
	ctx := bfvpack.NewContext()

	var trials []trial
	sizes := []size{{3, 5, 2, 8}, {8, 8, 6, 12}}

	for _, s := range sizes {
		trials = append(trials, matmulSelectiveScaling(ctx, f, s)...)
		trials = append(trials, matmulKernel(ctx, f, s)...)
		trials = append(trials, squareAttacks(ctx, f, s)...)
	}

	// capability matrix summary
	type capRow struct {
		Attack        string `json:"attack"`
		HonestMinimal string `json:"under_honest_minimal"`
		Extended      string `json:"under_extended"`
		NeedsRelin    bool   `json:"needs_relin_beyond_honest"`
		NeedsRowRot   bool   `json:"needs_row_rotations_beyond_honest"`
	}
	writeJSON(outDir+"/trials.json", map[string]interface{}{
		"schema": "trial",
		"note":   "capability_profile=honest_minimal grants only the keys the honest function needs (matmul: column offsets, no relin; squaring: relin, no rotations). extended adds attack-specific rotations/relin. Outcome unsupported_capability under honest_minimal means the forgery is NOT a direct attack at that profile.",
		"trials": trials,
	})
	fmt.Println("wrote", outDir, "trials:", len(trials))
}

func honestMatmulKeys(ctx bfvpack.Context, d, ell int) bfvpack.Capability {
	return bfvpack.Capability{Relin: false, Rotations: bfvpack.PublicMatmulRotations(d, ell)}
}

func matmulSelectiveScaling(ctx bfvpack.Context, f field.Field, s size) []trial {
	a := rnd(f, s.n, s.d, 1)
	b := rnd(f, s.d, s.ell, 2)
	key := dataseal.MatmulKey{K: rnd(f, s.n, 1, 3).Col(0), Alpha: 7}
	e := dataseal.MatmulEncode(f, a, b, key)
	correct := matrix.Mul(f, a, b)
	var out []trial
	// honest_minimal: selective scaling needs only a plaintext mult (no rotation, no relin)
	for _, prof := range []string{"honest_minimal", "extended"} {
		cap := honestMatmulKeys(ctx, s.d, s.ell)
		if prof == "extended" {
			cap.Relin = true
		}
		k := ctx.KeyGen(cap)
		in := k.Encrypt(e.AStar, bfvpack.MakeLayout(s.n+2, s.d, s.n, s.dim))
		honest := k.PublicRightMatmul(in, b, s.ell)
		hc := k.Decrypt(honest)
		k.ResetCount()
		var changed bfvpack.Cipher
		oc := capture(func() string {
			changed = attacks.SelectiveScaling(k, f, honest, s.n, 3)
			c1 := k.Decrypt(changed)
			acc := dataseal.MatmulVerify(f, e.Client, c1, dataseal.Original).Accepted()
			return classify(acc, hc, c1, c1.TopRows(s.n), correct)
		})
		cnt := k.CountSnapshot()
		out = append(out, trial{
			Attack: "selective_scaling", Verifier: "dataseal_original", Capability: prof,
			N: s.n, D: s.d, Ell: s.ell, KeysRelin: cap.Relin, KeysRot: cap.Rotations,
			Rotate: cnt.Rotate, MulPt: cnt.MulPt, MulCt: cnt.MulCt, Add: cnt.Add,
			Outcome: oc, Note: "plaintext-mult only; strengthened verifier rejects (negative control below)",
		})
		// negative control: strengthened verifier
		if prof == "extended" {
			k2 := ctx.KeyGen(cap)
			in2 := k2.Encrypt(e.AStar, bfvpack.MakeLayout(s.n+2, s.d, s.n, s.dim))
			honest2 := k2.PublicRightMatmul(in2, b, s.ell)
			c1 := k2.Decrypt(attacks.SelectiveScaling(k2, f, honest2, s.n, 3))
			acc := dataseal.MatmulVerify(f, e.Client, c1, dataseal.Strengthened).Accepted()
			out = append(out, trial{
				Attack: "selective_scaling", Verifier: "dataseal_strengthened", Capability: prof,
				N: s.n, D: s.d, Ell: s.ell, KeysRelin: cap.Relin, KeysRot: cap.Rotations,
				Outcome: classify(acc, k2.Decrypt(honest2), c1, c1.TopRows(s.n), correct),
				Note:    "negative control: strengthened must reject (rejected_wrong)",
			})
		}
	}
	return out
}

func matmulKernel(ctx bfvpack.Context, f field.Field, s size) []trial {
	a := rnd(f, s.n, s.d, 4)
	b := rnd(f, s.d, s.ell, 5)
	key := dataseal.MatmulKey{K: rnd(f, s.n, 1, 6).Col(0), Alpha: 7}
	e := dataseal.MatmulEncode(f, a, b, key)
	correct := matrix.Mul(f, a, b)
	ch := attacks.KernelChoice{ColA: 0, ColB: 1, Target: 0}
	var out []trial
	for _, prof := range []string{"honest_minimal", "extended"} {
		cap := honestMatmulKeys(ctx, s.d, s.ell)
		note := "kernel uses ct*ct (needs relin) and row-shift rotations (n*Dim, -i*Dim) absent from honest matmul keys"
		if prof == "extended" {
			cap.Relin = true
			cap.Rotations = append(cap.Rotations, kernelRots(s.n, s.dim, ch)...)
		}
		k := ctx.KeyGen(cap)
		in := k.Encrypt(e.AStar, bfvpack.MakeLayout(s.n+2, s.d, s.n, s.dim))
		honest := k.PublicRightMatmul(in, b, s.ell)
		hc := k.Decrypt(honest)
		k.ResetCount()
		var acc bool
		var c1 matrix.Mat
		oc := capture(func() string {
			changed := attacks.KernelAdjustedOutput(k, in, honest, s.n, ch)
			c1 = k.Decrypt(changed)
			acc = dataseal.MatmulVerify(f, e.Client, c1, dataseal.Strengthened).Accepted()
			return classify(acc, hc, c1, c1.TopRows(s.n), correct)
		})
		cnt := k.CountSnapshot()
		out = append(out, trial{
			Attack: "encrypted_kernel", Verifier: "dataseal_strengthened", Capability: prof,
			N: s.n, D: s.d, Ell: s.ell, KeysRelin: cap.Relin, KeysRot: cap.Rotations,
			Rotate: cnt.Rotate, MulPt: cnt.MulPt, MulCt: cnt.MulCt, Add: cnt.Add,
			Outcome: oc, Note: note,
		})
	}
	return out
}

func squareAttacks(ctx bfvpack.Context, f field.Field, s size) []trial {
	// square uses D columns; use n data rows, D cols
	a := rnd(f, s.n, s.d, 7)
	eta := rnd(f, s.d, 1, 8).Col(0)
	e := dataseal.SquareEncode(f, a, eta)
	correct := matrix.Square(f, a)
	dim := s.dim
	var out []trial
	// honest squaring key set: relin (ct*ct), NO rotations.
	for _, prof := range []string{"honest_minimal", "extended"} {
		// --- rescale: plaintext-mult only (honest_minimal) ---
		capR := bfvpack.Capability{Relin: true}
		kR := ctx.KeyGen(capR)
		inR := kR.Encrypt(e.AStar, bfvpack.MakeLayout(s.n+1, s.d, s.n, dim))
		honR := kR.Square(inR)
		hcR := kR.Decrypt(honR)
		kR.ResetCount()
		ocR := capture(func() string {
			c1 := kR.Decrypt(attacks.SquareRescale(kR, f, honR, 1%s.d, 0, min(2, s.n-1), 3))
			acc := dataseal.SquareVerify(f, e.Client, c1).Accepted()
			return classify(acc, hcR, c1, c1.TopRows(s.n), correct)
		})
		cR := kR.CountSnapshot()
		if prof == "honest_minimal" { // rescale needs no rotations; report once at minimal
			out = append(out, trial{
				Attack: "square_rescale", Verifier: "dataseal_square", Capability: "honest_minimal",
				N: s.n, D: s.d, Ell: s.d, KeysRelin: true, KeysRot: nil,
				Rotate: cR.Rotate, MulPt: cR.MulPt, MulCt: cR.MulCt, Add: cR.Add,
				Outcome: ocR, Note: "plaintext gamma/gamma^-1 mult; no rotation needed",
			})
		}

		// --- permute: row-shift rotations, absent from honest squaring keys ---
		capP := bfvpack.Capability{Relin: true}
		rot := []int{}
		if prof == "extended" {
			rot = []int{2 * dim, -2 * dim}
		}
		capP.Rotations = rot
		kP := ctx.KeyGen(capP)
		inP := kP.Encrypt(e.AStar, bfvpack.MakeLayout(s.n+1, s.d, s.n, dim))
		honP := kP.Square(inP)
		hcP := kP.Decrypt(honP)
		kP.ResetCount()
		ocP := capture(func() string {
			c1 := kP.Decrypt(attacks.SquarePermute(kP, honP, s.n, 0, min(2, s.n-1), 1%s.d))
			acc := dataseal.SquareVerify(f, e.Client, c1).Accepted()
			return classify(acc, hcP, c1, c1.TopRows(s.n), correct)
		})
		cP := kP.CountSnapshot()
		out = append(out, trial{
			Attack: "square_permute", Verifier: "dataseal_square", Capability: prof,
			N: s.n, D: s.d, Ell: s.d, KeysRelin: true, KeysRot: rot,
			Rotate: cP.Rotate, MulPt: cP.MulPt, MulCt: cP.MulCt, Add: cP.Add,
			Outcome: ocP, Note: "swaps two data rows in one column via +-2*Dim row rotations",
		})
	}
	return out
}

// kernelRots mirrors the attack test's required offsets for the kernel column.
func kernelRots(n, dim int, ch attacks.KernelChoice) []int {
	set := map[int]bool{ch.ColA - ch.Target: true, ch.ColB - ch.Target: true, n * dim: true}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

func writeJSON(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}
