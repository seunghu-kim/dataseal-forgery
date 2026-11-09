// Command finaleval is the F5 corrected performance benchmark. It supersedes
// cmd/finalbench (G9) with: nanosecond raw timing + batching for sub-microsecond
// stages; explicit client/server/verifier stage separation; per-single-
// evaluation operation counts; ciphertext and evaluation-key byte sizes for
// every method including VERITAS; FHE-only acceptance reported as N/A; DataSeal
// input (W,G) vs program (U0,Z) preprocessing split; private-sketch
// Keygen/Register/Prepare split with corrected state byte accounting; capacity-
// aware 128 tiling for DataSeal (primary) with straightforward as a sensitivity
// row; and client-crossover (once vs reuse) components. Historical G9 outputs in
// results/lattigo/final/ are preserved; corrected outputs go to
// results/lattigo/final_v2/.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/ldsec/lattigo/v2/bfv"

	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
	"dsfgo/veritas"
)

type budget struct{ warmup, trials int }

func budgetFor(n int) budget {
	switch {
	case n <= 16:
		return budget{2, 12}
	case n <= 32:
		return budget{1, 8}
	case n <= 64:
		return budget{1, 5}
	default:
		return budget{1, 4}
	}
}

type stat struct {
	MedianMs float64 `json:"median_ms"`
	P10Ms    float64 `json:"p10_ms"`
	P90Ms    float64 `json:"p90_ms"`
	Trials   int     `json:"trials"`
	Batch    int     `json:"batch"`
}

func pctl(xs []float64, p float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(p * float64(len(s)-1))
	return s[i]
}

// timeStat runs fn `batch` times per trial, records nanoseconds, and divides by
// batch so sub-microsecond stages are not truncated to zero.
func timeStat(b budget, batch int, fn func()) stat {
	if batch < 1 {
		batch = 1
	}
	for i := 0; i < b.warmup; i++ {
		fn()
	}
	raw := make([]float64, b.trials)
	for i := 0; i < b.trials; i++ {
		t0 := time.Now()
		for j := 0; j < batch; j++ {
			fn()
		}
		raw[i] = float64(time.Since(t0).Nanoseconds()) / float64(batch) / 1e6
	}
	return stat{pctl(raw, 0.5), pctl(raw, 0.1), pctl(raw, 0.9), b.trials, batch}
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

type cell struct {
	Config   string `json:"config"`
	Param    string `json:"param"`
	Layout   string `json:"layout"`
	Flag     string `json:"comparability_flag"`
	N        int    `json:"n"`
	D        int    `json:"d"`
	Ell      int    `json:"ell"`
	Dim      int    `json:"padded_dim"`
	Tiles    int    `json:"input_tiles"`
	Exact    bool   `json:"exact_match"`
	Accepted string `json:"accepted"` // "true"|"false"|"N/A"

	Keygen      stat `json:"keygen"`
	InputPrep   stat `json:"input_prep"`
	Encrypt     stat `json:"encrypt"`
	ProgramPrep stat `json:"program_prep"`
	Server      stat `json:"server_eval"`
	Decrypt     stat `json:"decrypt"`
	Verify      stat `json:"verification"`
	Plaintext   stat `json:"direct_plaintext"`

	ClientOnceMs  float64 `json:"client_total_once_ms"`
	ClientReuseMs float64 `json:"client_total_reuse_ms"`

	OpRotate int `json:"op_rotate_per_eval"`
	OpMulPt  int `json:"op_mul_pt_per_eval"`
	OpMulCt  int `json:"op_mul_ct_per_eval"`
	OpAdd    int `json:"op_add_per_eval"`

	InputBytes   int `json:"input_ct_bytes"`
	OutputBytes  int `json:"output_ct_bytes"`
	EvalKeyBytes int `json:"eval_key_bytes"`

	StateKeyBytes     int `json:"client_state_key_bytes"`     // reusable key material (sketch K / dataseal K,alpha)
	StateInputBytes   int `json:"client_state_input_bytes"`   // per-input verification state (sketch W; dataseal checksum rows in ct)
	StateProgramBytes int `json:"client_state_program_bytes"` // per-program expected values (sketch T; dataseal U0,Z)
}

const tileCol = 64

func elemBytes(n int) int { return 8 * n }

// runBFVCell times one BFV-group config at one size.
func runBFVCell(ctx bfvpack.Context, config, layout string, n, d, ell int) cell {
	f := ctx.Field()
	bud := budgetFor(n)
	c := cell{Config: config, Param: "PN14QP438", Layout: layout, Flag: "PASS", N: n, D: d, Ell: ell}
	a := rnd(f, n, d, 1)
	b := rnd(f, d, ell, 2)
	want := matrix.Mul(f, a, b)
	c.Plaintext = timeStat(bud, 50, func() { _ = matrix.Mul(f, a, b) })

	checksum := 0
	if config == "dataseal_original" || config == "dataseal_strengthened" {
		checksum = 2
	}
	plan := bfvpack.PlanMatmul(config, n, d, ell, checksum, tileCol, "PN14QP438")
	tiled := plan.Strategy == bfvpack.StrategyTiled

	// --- client input preparation (checksum rows / registration) ---
	encoded := a
	var dsClient dataseal.MatmulClient
	var dsKey dataseal.MatmulKey
	var skClient sketch.Client
	var skProgram sketch.Program
	switch config {
	case "dataseal_original", "dataseal_strengthened":
		dsKey = dataseal.MatmulKey{K: rnd(f, n, 1, 3).Col(0), Alpha: 7}
		c.InputPrep = timeStat(bud, 20, func() { _, _ = dataseal.MatmulInputChecksum(f, a, dsKey) })
		w, g := dataseal.MatmulInputChecksum(f, a, dsKey)
		c.ProgramPrep = timeStat(bud, 20, func() { _, _ = dataseal.MatmulExpected(f, b, w, g) })
		e := dataseal.MatmulEncode(f, a, b, dsKey)
		dsClient = e.Client
		encoded = e.AStar
		c.StateKeyBytes = elemBytes(len(dsKey.K) + 1)                       // K (n) + alpha
		c.StateInputBytes = elemBytes(2 * d)                                // W,G checksum rows (also carried in ct)
		c.StateProgramBytes = elemBytes(len(dsClient.U0) + len(dsClient.Z)) // U0,Z
	case "private_sketch":
		r := sketch.RowsFor(65537, 128, 1<<32)
		c.Keygen = timeStat(budget{1, 3}, 1, func() { _ = sketch.Keygen(f, r, n) })
		skClient = sketch.Keygen(f, r, n)
		sv := sketch.NewServer()
		c.InputPrep = timeStat(bud, 5, func() {
			cs := sketch.Keygen(f, r, n)
			s2 := sketch.NewServer()
			sketch.Register(f, &cs, &s2, "A", a)
		})
		sketch.Register(f, &skClient, &sv, "A", a)
		skProgram = sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b}}
		c.ProgramPrep = timeStat(bud, 5, func() { _ = sketch.Prepare(f, skClient, skProgram) })
		c.StateKeyBytes = elemBytes(r * n)   // K (r x n), reusable
		c.StateInputBytes = elemBytes(r * d) // W = K*A (r x d) per input
		c.StateProgramBytes = elemBytes(r * ell)
	}

	// --- HE keygen + program (mask) preparation ---
	var rots []int
	if tiled {
		if layout == "capacity_aware" {
			// rotations come from the capacity layout's own column blocking
			probe := ctx.KeyGen(bfvpack.Capability{})
			ec := probe.EncryptTiledCapacity(encoded, n, tileCol)
			rots = ec.MatmulRotations(ell)
		} else {
			rots = bfvpack.TiledMatmulRotations(d, ell, tileCol)
		}
	} else {
		rots = bfvpack.PublicMatmulRotations(d, ell)
	}
	c.Keygen = timeStat(budget{1, 3}, 1, func() { _ = ctx.KeyGen(bfvpack.Capability{Rotations: rots}) })
	k := ctx.KeyGen(bfvpack.Capability{Rotations: rots})
	c.EvalKeyBytes = k.EvalKeyBytes()

	var decrypted matrix.Mat
	if tiled {
		var ea bfvpack.TiledCipher
		if layout == "capacity_aware" {
			c.Encrypt = timeStat(bud, 1, func() { ea = k.EncryptTiledCapacity(encoded, n, tileCol) })
			ea = k.EncryptTiledCapacity(encoded, n, tileCol)
		} else {
			c.Encrypt = timeStat(bud, 1, func() { ea = k.EncryptTiled(encoded, tileCol) })
			ea = k.EncryptTiled(encoded, tileCol)
		}
		c.InputBytes = ea.Bytes()
		c.Tiles = ea.NumTiles()
		c.Dim = ea.Dim
		var out bfvpack.TiledCipher
		c.Server = timeStat(bud, 1, func() { out = k.PublicRightMatmulTiled(ea, b, ell) })
		out = k.PublicRightMatmulTiled(ea, b, ell)
		c.OutputBytes = out.Bytes()
		k.ResetCount()
		_ = k.PublicRightMatmulTiled(ea, b, ell)
		cs := k.CountSnapshot()
		c.OpRotate, c.OpMulPt, c.OpMulCt, c.OpAdd = cs.Rotate, cs.MulPt, cs.MulCt, cs.Add
		c.Decrypt = timeStat(bud, 1, func() { decrypted = k.DecryptTiled(out) })
	} else {
		layoutObj := bfvpack.MakeLayout(n+checksum, d, n, plan.SingleCtDim)
		c.Dim = plan.SingleCtDim
		c.Tiles = 1
		// HE program (mask) prep is part of the public-program preparation; for
		// bfv_only it is the only program prep.
		var prep bfvpack.PreparedMatmul
		if config == "bfv_only" {
			c.ProgramPrep = timeStat(bud, 1, func() { prep = k.PrepareMatmul(layoutObj, b, ell) })
		}
		prep = k.PrepareMatmul(layoutObj, b, ell)
		var ea bfvpack.Cipher
		c.Encrypt = timeStat(bud, 1, func() { ea = k.Encrypt(encoded, layoutObj) })
		ea = k.Encrypt(encoded, layoutObj)
		c.InputBytes = ea.Bytes()
		var out bfvpack.Cipher
		c.Server = timeStat(bud, 1, func() { out = k.ServerMatmul(ea, prep) })
		out = k.ServerMatmul(ea, prep)
		c.OutputBytes = out.Bytes()
		k.ResetCount()
		_ = k.ServerMatmul(ea, prep)
		cs := k.CountSnapshot()
		c.OpRotate, c.OpMulPt, c.OpMulCt, c.OpAdd = cs.Rotate, cs.MulPt, cs.MulCt, cs.Add
		c.Decrypt = timeStat(bud, 1, func() { decrypted = k.Decrypt(out) })
	}

	c.Exact = decrypted.TopRows(n).Equal(want)
	switch config {
	case "bfv_only":
		c.Accepted = "N/A" // no authenticator
	case "private_sketch":
		tp := sketch.Prepare(f, skClient, skProgram)
		var acc bool
		c.Verify = timeStat(bud, 20, func() { acc = sketch.Verify(f, skClient, tp, decrypted.TopRows(n)) })
		c.Accepted = boolStr(acc)
	default:
		mode := dataseal.Original
		if config == "dataseal_strengthened" {
			mode = dataseal.Strengthened
		}
		var acc bool
		c.Verify = timeStat(bud, 200, func() { acc = dataseal.MatmulVerify(f, dsClient, decrypted, mode).Accepted() })
		c.Accepted = boolStr(acc)
	}

	c.ClientOnceMs = c.InputPrep.MedianMs + c.Encrypt.MedianMs + c.ProgramPrep.MedianMs + c.Decrypt.MedianMs + c.Verify.MedianMs
	c.ClientReuseMs = c.ProgramPrep.MedianMs + c.Decrypt.MedianMs + c.Verify.MedianMs
	return c
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type veritasCell struct {
	Scheme    string `json:"scheme"`
	Param     string `json:"param"`
	Flag      string `json:"comparability_flag"`
	N         int    `json:"n"`
	Dim       int    `json:"dim"`
	NSlots    int    `json:"nslots"`
	Exact     bool   `json:"exact_match"`
	Accepted  bool   `json:"accepted_official_verifier"`
	InputPrep stat   `json:"input_prep"`
	ProgPrep  stat   `json:"program_prep"`
	Server    stat   `json:"server_eval"`
	VerifTags stat   `json:"verifier_tag_evolution"`
	Decode    stat   `json:"decode_verify"`
	OpRotate  int    `json:"op_rotate_per_eval"`
	OpMulPt   int    `json:"op_mul_pt_per_eval"`
	OpAdd     int    `json:"op_add_per_eval"`
	Note      string `json:"note"`
}

func main() {
	outDir := "../../results/lattigo/final_v2"
	if len(os.Args) == 2 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0o755)
	runtime.GOMAXPROCS(1)
	ctx := bfvpack.NewContext()
	f := ctx.Field()

	// ---- Panel 1: BFV-group matmul sweep (primary) ----
	sizes := []int{8, 16, 32, 64, 128}
	var cells []cell
	for _, n := range sizes {
		fmt.Printf("bfv sweep n=%d\n", n)
		cells = append(cells, runBFVCell(ctx, "bfv_only", "primary", n, n, n))
		dsLayout := "primary"
		if n == 128 {
			dsLayout = "capacity_aware"
		}
		cells = append(cells, runBFVCell(ctx, "dataseal_original", dsLayout, n, n, n))
		cells = append(cells, runBFVCell(ctx, "dataseal_strengthened", dsLayout, n, n, n))
		cells = append(cells, runBFVCell(ctx, "private_sketch", "primary", n, n, n))
		// sensitivity: straightforward DataSeal at 128
		if n == 128 {
			cells = append(cells, runBFVCell(ctx, "dataseal_original", "straightforward", n, n, n))
		}
	}
	writeJSON(outDir+"/matmul_sweep.json", map[string]interface{}{
		"schema": "cell", "base_param": "PN14QP438", "tile_col": tileCol, "gomaxprocs": 1,
		"note":  "timing ns + batching; per-eval op counts; FHE-only accepted=N/A; DataSeal 128 uses capacity_aware primary with straightforward as sensitivity. bfv_only/dataseal/sketch share the server circuit; strengthened shares original's ciphertext/server op (verifier-only change).",
		"cells": cells,
	})

	// ---- Panel 2: VERITAS authenticated matmul (phase-separated, PN13) ----
	var vcells []veritasCell
	for _, s := range []struct{ n, inner, ell, dim int }{{2, 2, 2, 4}, {4, 4, 4, 8}, {8, 8, 8, 16}, {16, 16, 16, 32}} {
		rm := veritas.NewRepMatmul(bfv.PN13QP218, 4, veritas.RotationsFor(s.inner, s.ell))
		if s.dim*s.dim <= rm.NSlots/2 {
			vcells = append(vcells, repCell(f, rm, s.n, s.inner, s.ell, s.dim))
		}
		pm := veritas.NewPeMatmul(bfv.PN13QP218, veritas.RotationsFor(s.inner, s.ell))
		if s.dim*s.dim <= pm.NSlots/2 {
			vcells = append(vcells, peCell(f, pm, s.n, s.inner, s.ell, s.dim))
		}
	}
	writeJSON(outDir+"/veritas_matmul.json", map[string]interface{}{
		"schema": "veritasCell",
		"note":   "Phase-separated: server_eval is ServerEval only (ciphertext + public masks + rotation keys; no secret/verif). PARAMETER_MISMATCH vs the PN14 BFV group; within-scheme stage splits are valid.",
		"cells":  vcells,
	})

	// ---- Panel 3: r-sweep with soundness bound ----
	n, ell := 32, 32
	A := rnd(f, n, n, 7)
	B := rnd(f, n, ell, 8)
	C := matrix.Mul(f, A, B)
	const p = 65537
	const qAuth = float64(1 << 32)
	var sweep []map[string]interface{}
	for _, r := range []int{1, 2, 4, 8, 10} {
		cs := sketch.Client{K: sketch.RandomMat(f, r, n), Regs: map[string]sketch.Registration{}}
		sv := sketch.NewServer()
		sketch.Register(f, &cs, &sv, "A", A)
		prog := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: B}}
		tp := sketch.Prepare(f, cs, prog)
		st := timeStat(budget{2, 12}, 200, func() { _ = sketch.Verify(f, cs, tp, C) })
		bound := math.Min(1, qAuth*math.Pow(float64(p), -float64(r)))
		sweep = append(sweep, map[string]interface{}{
			"r": r, "verify_ms": st.MedianMs, "p10_ms": st.P10Ms, "p90_ms": st.P90Ms,
			"soundness_bound_min1_Qp_minus_r": bound, "p": p, "Q_auth": "2^32",
		})
	}
	writeJSON(outDir+"/sketch_r_sweep.json", map[string]interface{}{
		"n": n, "ell": ell,
		"note":  "Q_auth=2^32 standardized; verify linear in r; soundness min(1,Q*p^-r). r=1 (bound 1.0) is NOT the same authentication security as r=10. FHE bit-security is a separate, UNVERIFIED axis (see reports/security_parameters.md).",
		"sweep": sweep,
	})

	writeJSON(outDir+"/env.json", map[string]interface{}{
		"go_version": runtime.Version(), "goarch": runtime.GOARCH, "goos": runtime.GOOS,
		"gomaxprocs": 1, "base_param": "PN14QP438", "veritas_param": "PN13QP218",
		"lattigo_pin": "github.com/ldsec/lattigo/v2 v2.2.1-0.20210923173451-d9eb44f2c43f",
		"note":        "single-thread; corrected F5 methodology (see reports/final_benchmark_methodology_audit.md)",
	})
	fmt.Println("wrote", outDir)
}

func repCell(f field.Field, rm veritas.RepMatmul, n, inner, ell, dim int) veritasCell {
	bud := budgetFor(n)
	a := rnd(f, n, inner, 3)
	b := rnd(f, inner, ell, 4)
	want := matrix.Mul(f, a, b)
	var in veritas.RepInput
	ip := timeStat(bud, 1, func() { in = rm.ClientEncrypt(a, dim) })
	in = rm.ClientEncrypt(a, dim)
	var prog veritas.RepProgram
	pp := timeStat(bud, 1, func() { prog = rm.PrepareProgram(b, n, ell, dim) })
	prog = rm.PrepareProgram(b, n, ell, dim)
	var ct = rm.ServerEval(in.Ct, prog)
	sv := timeStat(bud, 1, func() { ct = rm.ServerEval(in.Ct, prog) })
	var verif = rm.VerifierTags(in.Verif, prog)
	vt := timeStat(bud, 1, func() { verif = rm.VerifierTags(in.Verif, prog) })
	var got matrix.Mat
	var ok bool
	dec := timeStat(bud, 1, func() { got, ok = rm.DecodeVerify(ct, verif, prog) })
	ops := prog.Ops()
	return veritasCell{
		Scheme: "veritas_rep", Param: "PN13QP218", Flag: "PARAMETER_MISMATCH",
		N: n, Dim: dim, NSlots: rm.NSlots, Exact: got.Equal(want), Accepted: ok,
		InputPrep: ip, ProgPrep: pp, Server: sv, VerifTags: vt, Decode: dec,
		OpRotate: ops.Rotate, OpMulPt: ops.MulPt, OpAdd: ops.Add,
		Note: "official vche_1; numReplications=4; PN13 native",
	}
}

func peCell(f field.Field, pm veritas.PeMatmul, n, inner, ell, dim int) veritasCell {
	bud := budgetFor(n)
	a := rnd(f, n, inner, 5)
	b := rnd(f, inner, ell, 6)
	want := matrix.Mul(f, a, b)
	var in veritas.PeInput
	ip := timeStat(bud, 1, func() { in = pm.ClientEncrypt(a, dim) })
	in = pm.ClientEncrypt(a, dim)
	var prog veritas.PeProgram
	pp := timeStat(bud, 1, func() { prog = pm.PrepareProgram(b, n, ell, dim) })
	prog = pm.PrepareProgram(b, n, ell, dim)
	var ct = pm.ServerEval(in.Ct, prog)
	sv := timeStat(bud, 1, func() { ct = pm.ServerEval(in.Ct, prog) })
	var verif = pm.VerifierTags(in.Verif, prog)
	vt := timeStat(bud, 1, func() { verif = pm.VerifierTags(in.Verif, prog) })
	var got matrix.Mat
	var ok bool
	dec := timeStat(bud, 1, func() { got, ok = pm.DecodeVerify(ct, verif, prog) })
	ops := prog.Ops()
	return veritasCell{
		Scheme: "veritas_pe", Param: "PN13QP218", Flag: "PARAMETER_MISMATCH",
		N: n, Dim: dim, NSlots: pm.NSlots, Exact: got.Equal(want), Accepted: ok,
		InputPrep: ip, ProgPrep: pp, Server: sv, VerifTags: vt, Decode: dec,
		OpRotate: ops.Rotate, OpMulPt: ops.MulPt, OpAdd: ops.Add,
		Note: "official vche_2 (unoptimized decode); PN13 native",
	}
}

func writeJSON(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}
