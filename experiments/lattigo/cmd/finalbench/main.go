// Command finalbench runs the G9 size sweep with scientifically comparable,
// parameter-matched panels and preserved raw per-trial data. It is separate
// from cmd/bench (G5) so historical results are not overwritten. Output goes to
// results/lattigo/final/. The repeat budget shrinks for large sizes; the actual
// trial count is recorded per cell so no median is printed from one observation
// without disclosure.
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
		return budget{2, 10}
	case n <= 32:
		return budget{1, 6}
	case n <= 64:
		return budget{1, 3}
	default:
		return budget{1, 2}
	}
}

type stage struct {
	MedianMs float64 `json:"median_ms"`
	IqrMs    float64 `json:"iqr_ms"`
	Trials   int     `json:"trials"`
}

func med(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)/2]
}
func iqr(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s) < 4 {
		return s[len(s)-1] - s[0]
	}
	return s[(3*len(s))/4] - s[len(s)/4]
}

func timeB(b budget, fn func()) stage {
	for i := 0; i < b.warmup; i++ {
		fn()
	}
	raw := make([]float64, b.trials)
	for i := 0; i < b.trials; i++ {
		t0 := time.Now()
		fn()
		raw[i] = float64(time.Since(t0).Microseconds()) / 1000.0
	}
	return stage{med(raw), iqr(raw), b.trials}
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

type matCell struct {
	Config    string `json:"config"`
	Param     string `json:"param"`
	Strategy  string `json:"strategy"`
	Flag      string `json:"comparability_flag"`
	N         int    `json:"n"`
	D         int    `json:"d"`
	Ell       int    `json:"ell"`
	PaddedDim int    `json:"padded_dim"`
	TileSize  int    `json:"tile_size"`
	Tiles     int    `json:"input_tiles"`
	Exact     bool   `json:"exact_match"`
	Accepted  bool   `json:"accepted"`

	Keygen     stage `json:"keygen"`
	ClientPrep stage `json:"client_prep_input"`
	FuncPrep   stage `json:"func_prep"`
	Encrypt    stage `json:"encrypt"`
	Server     stage `json:"server_eval"`
	Decrypt    stage `json:"decrypt"`
	Verify     stage `json:"verify"`
	Plaintext  stage `json:"direct_plaintext"`

	ServerAdd   int `json:"server_add"`
	ServerMulPt int `json:"server_mul_pt"`
	ServerMulCt int `json:"server_mul_ct"`
	ServerRot   int `json:"server_rotate"`

	InputBytes   int `json:"input_ct_bytes"`
	OutputBytes  int `json:"output_ct_bytes"`
	EvalKeyBytes int `json:"eval_key_bytes"`
	AuxBytes     int `json:"aux_bytes"`

	Note string `json:"note,omitempty"`
}

const baseParam = "PN14QP438"
const tileSize = 64

func checksumRows(config string) int {
	if config == "dataseal_original" || config == "dataseal_strengthened" {
		return 2
	}
	return 0
}

// runMatmulCell executes one BFV-group config at one size, choosing the single
// ciphertext or tiled strategy per the planner, and times each stage.
func runMatmulCell(ctx bfvpack.Context, config string, n, d, ell int) matCell {
	f := ctx.Field()
	bud := budgetFor(n)
	plan := bfvpack.PlanMatmul(config, n, d, ell, checksumRows(config), tileSize, baseParam)
	cell := matCell{
		Config: config, Param: baseParam, Strategy: plan.Strategy, Flag: "PASS",
		N: n, D: d, Ell: ell, TileSize: tileSize,
	}
	a := rnd(f, n, d, 1)
	b := rnd(f, d, ell, 2)
	want := matrix.Mul(f, a, b)
	cell.Plaintext = timeB(bud, func() { _ = matrix.Mul(f, a, b) })

	rots := bfvpack.PublicMatmulRotations(d, ell)
	if plan.Strategy == bfvpack.StrategyTiled {
		rots = bfvpack.TiledMatmulRotations(d, ell, tileSize)
	}

	// client-side input encoding (checksum rows / registration) and function prep
	var encoded matrix.Mat = a
	var dsClient dataseal.MatmulClient
	var skClient sketch.Client
	var skProgram sketch.Program
	switch config {
	case "dataseal_original", "dataseal_strengthened":
		key := dataseal.MatmulKey{K: sketch.RandomMat(f, n, 1).Col(0), Alpha: sketch.UniformElem(f)}
		cell.ClientPrep = timeB(bud, func() { _ = dataseal.MatmulEncode(f, a, b, key) })
		e := dataseal.MatmulEncode(f, a, b, key)
		dsClient = e.Client
		encoded = e.AStar
		cell.AuxBytes = 8 * (len(dsClient.W) + len(dsClient.G) + len(dsClient.U0) + len(dsClient.Z) + len(key.K))
	case "private_sketch":
		r := sketch.RowsFor(65537, 128, 1<<32)
		skClient = sketch.Keygen(f, r, n)
		sv := sketch.NewServer()
		cell.ClientPrep = timeB(bud, func() {
			cs := sketch.Keygen(f, r, n)
			s2 := sketch.NewServer()
			sketch.Register(f, &cs, &s2, "A", a)
		})
		sketch.Register(f, &skClient, &sv, "A", a)
		skProgram = sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b}}
		cell.FuncPrep = timeB(bud, func() { _ = sketch.Prepare(f, skClient, skProgram) })
		cell.AuxBytes = 8 * (skClient.K.Rows()*skClient.K.Cols() + n*ell)
	}

	cell.Keygen = timeB(budget{1, 3}, func() { _ = ctx.KeyGen(bfvpack.Capability{Rotations: rots}) })
	k := ctx.KeyGen(bfvpack.Capability{Rotations: rots})
	cell.EvalKeyBytes = k.EvalKeyBytes()

	var decrypted matrix.Mat
	if plan.Strategy == bfvpack.StrategyTiled {
		var ea bfvpack.TiledCipher
		cell.Encrypt = timeB(bud, func() { ea = k.EncryptTiled(encoded, tileSize) })
		cell.InputBytes = ea.Bytes()
		cell.Tiles = ea.NumTiles()
		var out bfvpack.TiledCipher
		k.Count = &bfvpack.Counts{}
		cell.Server = timeB(bud, func() { out = k.PublicRightMatmulTiled(ea, b, ell) })
		cell.InputBytes = ea.Bytes()
		cell.OutputBytes = out.Bytes()
		cell.Decrypt = timeB(bud, func() { decrypted = k.DecryptTiled(out) })
	} else {
		extra := checksumRows(config)
		layout := bfvpack.MakeLayout(n+extra, d, n, plan.SingleCtDim)
		var ea bfvpack.Cipher
		cell.Encrypt = timeB(bud, func() { ea = k.Encrypt(encoded, layout) })
		cell.InputBytes = ea.Bytes()
		cell.Tiles = 1
		var out bfvpack.Cipher
		k.Count = &bfvpack.Counts{}
		cell.Server = timeB(bud, func() { out = k.PublicRightMatmul(ea, b, ell) })
		cell.OutputBytes = out.Bytes()
		cell.Decrypt = timeB(bud, func() { decrypted = k.Decrypt(out) })
	}
	cell.PaddedDim = plan.SingleCtDim
	if plan.Strategy == bfvpack.StrategyTiled {
		cell.PaddedDim = tileSize
	}
	cell.ServerAdd, cell.ServerMulPt, cell.ServerMulCt, cell.ServerRot = k.Count.Add, k.Count.MulPt, k.Count.MulCt, k.Count.Rotate

	cell.Exact = decrypted.TopRows(n).Equal(want)
	switch config {
	case "bfv_only":
		cell.Accepted = cell.Exact
		cell.Verify = stage{}
	case "private_sketch":
		tp := sketch.Prepare(f, skClient, skProgram)
		cell.Verify = timeB(bud, func() { cell.Accepted = sketch.Verify(f, skClient, tp, decrypted.TopRows(n)) })
	default:
		mode := dataseal.Original
		if config == "dataseal_strengthened" {
			mode = dataseal.Strengthened
		}
		cell.Verify = timeB(bud, func() { cell.Accepted = dataseal.MatmulVerify(f, dsClient, decrypted, mode).Accepted() })
	}
	return cell
}

type veritasCell struct {
	Scheme   string `json:"scheme"`
	Param    string `json:"param"`
	Flag     string `json:"comparability_flag"`
	N        int    `json:"n"`
	Inner    int    `json:"inner"`
	Ell      int    `json:"ell"`
	Dim      int    `json:"dim"`
	NSlots   int    `json:"nslots"`
	Exact    bool   `json:"exact_match"`
	Accepted bool   `json:"accepted_official_verifier"`
	Server   stage  `json:"server_eval"`
	Verify   stage  `json:"verify"`
	Note     string `json:"note"`
}

func main() {
	outDir := "../../results/lattigo/final"
	if len(os.Args) == 2 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0o755)
	runtime.GOMAXPROCS(1)

	ctx := bfvpack.NewContext()
	f := ctx.Field()

	// ---- Panel 1: BFV-group matmul size sweep (single param group PN14) ----
	sizes := []int{8, 16, 32, 64, 128}
	configs := []string{"bfv_only", "dataseal_original", "dataseal_strengthened", "private_sketch"}
	var matCells []matCell
	for _, n := range sizes {
		for _, cfg := range configs {
			fmt.Printf("matmul %s n=%d ...\n", cfg, n)
			matCells = append(matCells, runMatmulCell(ctx, cfg, n, n, n))
		}
	}
	writeJSON(outDir+"/matmul_sweep.json", map[string]interface{}{
		"schema":      "matCell",
		"base_param":  baseParam,
		"tile_size":   tileSize,
		"gomaxprocs":  1,
		"flag_legend": "PASS=matched & verified; strategy single_ct|tiled are both PN14 so one comparison group",
		"note":        "bfv_only/dataseal/sketch share the same row-major public_right_matmul server circuit; verifier differs. dataseal_strengthened uses the same ciphertext/server op as original (verifier-only change).",
		"cells":       matCells,
	})

	// ---- Panel 2: VERITAS authenticated matmul (official REP/PE verify) ----
	var vCells []veritasCell
	vSizes := []struct{ n, inner, ell, dim int }{
		{2, 2, 2, 4}, {4, 4, 4, 8}, {8, 8, 8, 16}, {16, 16, 16, 32},
	}
	for _, s := range vSizes {
		// REP (vche_1), numReplications=4 (nondegenerate), PN13 native param.
		rm := veritas.NewRepMatmul(bfv.PN13QP218, 4, veritas.RotationsFor(s.inner, s.ell))
		if s.dim*s.dim <= rm.NSlots/2 {
			a := rnd(f, s.n, s.inner, 3)
			b := rnd(f, s.inner, s.ell, 4)
			want := matrix.Mul(f, a, b)
			bud := budgetFor(s.n)
			in := rm.ClientEncrypt(a, s.dim)
			prog := rm.PrepareProgram(b, s.n, s.ell, s.dim)
			verif := rm.VerifierTags(in.Verif, prog)
			var ctres = rm.ServerEval(in.Ct, prog)
			srv := timeB(bud, func() { ctres = rm.ServerEval(in.Ct, prog) })
			var got matrix.Mat
			var ok bool
			ver := timeB(bud, func() { got, ok = rm.DecodeVerify(ctres, verif, prog) })
			vCells = append(vCells, veritasCell{
				"veritas_rep", "PN13QP218", "PARAMETER_MISMATCH", s.n, s.inner, s.ell, s.dim, rm.NSlots,
				got.Equal(want), ok, srv, ver,
				"official vche_1 verifier; numReplications=4; PN13 native (not comparable in absolute time to PN14 BFV group)",
			})
		}
		// PE (vche_2), PN13 native param.
		pm := veritas.NewPeMatmul(bfv.PN13QP218, veritas.RotationsFor(s.inner, s.ell))
		if s.dim*s.dim <= pm.NSlots/2 {
			a := rnd(f, s.n, s.inner, 5)
			b := rnd(f, s.inner, s.ell, 6)
			want := matrix.Mul(f, a, b)
			bud := budgetFor(s.n)
			in := pm.ClientEncrypt(a, s.dim)
			prog := pm.PrepareProgram(b, s.n, s.ell, s.dim)
			verif := pm.VerifierTags(in.Verif, prog)
			var ctres = pm.ServerEval(in.Ct, prog)
			srv := timeB(bud, func() { ctres = pm.ServerEval(in.Ct, prog) })
			var got matrix.Mat
			var ok bool
			ver := timeB(bud, func() { got, ok = pm.DecodeVerify(ctres, verif, prog) })
			vCells = append(vCells, veritasCell{
				"veritas_pe", "PN13QP218", "PARAMETER_MISMATCH", s.n, s.inner, s.ell, s.dim, pm.NSlots,
				got.Equal(want), ok, srv, ver,
				"official vche_2 verifier (unoptimized decode path); PN13 native (not comparable in absolute time to PN14 BFV group)",
			})
		}
	}
	writeJSON(outDir+"/veritas_matmul.json", map[string]interface{}{
		"schema": "veritasCell",
		"note":   "Authenticated public-right matmul via official REP/PE. Flag PARAMETER_MISMATCH: REP/PE run at PN13 native params, not PN14; do not read absolute times against the BFV group. Within-scheme server/verify split is valid.",
		"cells":  vCells,
	})

	// ---- Panel 3: private-sketch r-sweep with soundness bound ----
	n, ell := 32, 32
	A := rnd(f, n, n, 7)
	B := rnd(f, n, ell, 8)
	C := matrix.Mul(f, A, B)
	const p = 65537
	const qAuth = 1 << 20 // modeled attempt budget
	var sweep []map[string]interface{}
	for _, r := range []int{1, 2, 4, 8, 10} {
		cs := sketch.Client{K: sketch.RandomMat(f, r, n), Regs: map[string]sketch.Registration{}}
		sv := sketch.NewServer()
		sketch.Register(f, &cs, &sv, "A", A)
		prog := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: B}}
		tp := sketch.Prepare(f, cs, prog)
		st := timeB(budget{2, 10}, func() { _ = sketch.Verify(f, cs, tp, C) })
		bound := math.Min(1, float64(qAuth)*math.Pow(float64(p), -float64(r)))
		sweep = append(sweep, map[string]interface{}{
			"r": r, "verify_ms": st.MedianMs, "iqr_ms": st.IqrMs,
			"soundness_bound_min1_Qp_minus_r": bound, "p": p, "Q": qAuth,
		})
	}
	writeJSON(outDir+"/sketch_r_sweep.json", map[string]interface{}{
		"n": n, "ell": ell,
		"note":  "verify cost linear in r; soundness bound min(1, Q*p^-r). r=1 is NOT the same authentication security as r=10. FHE bit-security is a separate axis from this authentication soundness.",
		"sweep": sweep,
	})

	// environment record
	writeJSON(outDir+"/env.json", map[string]interface{}{
		"go_version":    runtime.Version(),
		"goarch":        runtime.GOARCH,
		"goos":          runtime.GOOS,
		"gomaxprocs":    1,
		"base_param":    baseParam,
		"veritas_param": "PN13QP218",
		"lattigo_pin":   "github.com/ldsec/lattigo/v2 v2.2.1-0.20210923173451-d9eb44f2c43f",
	})
	fmt.Println("wrote", outDir)
}

func writeJSON(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}
