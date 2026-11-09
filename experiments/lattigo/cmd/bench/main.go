// Command bench runs the unified Lattigo/BFV performance comparison (G5).
// All configurations are timed with the same manual median-of-trials harness to
// keep methodology uniform. Output is machine-readable JSON under results/lattigo.
package main

import (
	"encoding/json"
	"fmt"
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

const warmup = 2
const trials = 10

func med(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)/2]
}
func iqr(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[(3*len(s))/4] - s[len(s)/4]
}

func timeit(fn func()) (float64, float64) {
	for i := 0; i < warmup; i++ {
		fn()
	}
	raw := make([]float64, trials)
	for i := 0; i < trials; i++ {
		t0 := time.Now()
		fn()
		raw[i] = float64(time.Since(t0).Microseconds()) / 1000.0
	}
	return med(raw), iqr(raw)
}

type phase struct {
	MedianMs float64 `json:"median_ms"`
	IqrMs    float64 `json:"iqr_ms"`
}

func ph(fn func()) phase { m, q := timeit(fn); return phase{m, q} }

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

type matmulResult struct {
	Config      string  `json:"config"`
	PaddedDim   int     `json:"padded_dim"`
	Exact       bool    `json:"exact_match"`
	Accepted    bool    `json:"accepted"`
	ClientPrep  phase   `json:"client_prep"`
	Encrypt     phase   `json:"encrypt"`
	Server      phase   `json:"server_eval"`
	Decrypt     phase   `json:"decrypt"`
	Verify      phase   `json:"verify"`
	Plaintext   float64 `json:"direct_plaintext_ms"`
	ServerAdds  int     `json:"server_add"`
	ServerMulPt int     `json:"server_mul_pt"`
	ServerMulCt int     `json:"server_mul_ct"`
	ServerRot   int     `json:"server_rotate"`
}

// benchMatmul times a public-right matmul config on bfvpack.
func benchMatmul(c bfvpack.Context, config string, n, d, ell, D int) matmulResult {
	f := c.Field()
	a := rnd(f, n, d, 1)
	b := rnd(f, d, ell, 2)
	res := matmulResult{Config: config, PaddedDim: D}
	pl, _ := timeit(func() { _ = matrix.Mul(f, a, b) })
	res.Plaintext = pl

	rots := bfvpack.PublicMatmulRotations(d, ell)
	if config == "private_sketch" {
		// data-only, program eval via same public matmul; sketch prepared client-side.
		cs := sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n)
		sv := sketch.NewServer()
		res.ClientPrep = ph(func() {
			tmp := sketch.Keygen(f, 10, n)
			s2 := sketch.NewServer()
			sketch.Register(f, &tmp, &s2, "A", a)
		})
		sketch.Register(f, &cs, &sv, "A", a)
		k := c.KeyGen(bfvpack.Capability{Rotations: rots})
		var ea bfvpack.Cipher
		res.Encrypt = ph(func() { ea = k.Encrypt(a, bfvpack.MakeLayout(n, d, n, D)) })
		prog := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b}}
		var tp matrix.Mat
		_ = ph(func() { tp = sketch.Prepare(f, cs, prog) })
		var out bfvpack.Cipher
		k.Count = &bfvpack.Counts{}
		res.Server = ph(func() { out = k.PublicRightMatmul(ea, b, ell) })
		res.ServerAdds, res.ServerMulPt, res.ServerMulCt, res.ServerRot = k.Count.Add, k.Count.MulPt, k.Count.MulCt, k.Count.Rotate
		var y matrix.Mat
		res.Decrypt = ph(func() { y = k.Decrypt(out) })
		res.Verify = ph(func() { res.Accepted = sketch.Verify(f, cs, tp, y) })
		res.Exact = y.Equal(matrix.Mul(f, a, b))
		return res
	}

	extra := 0
	encoded := a
	var client dataseal.MatmulClient
	if config != "bfv_only" {
		extra = 2
		key := dataseal.MatmulKey{K: sketch.RandomMat(f, n, 1).Col(0), Alpha: sketch.UniformElem(f)}
		res.ClientPrep = ph(func() { _ = dataseal.MatmulEncode(f, a, b, key) })
		e := dataseal.MatmulEncode(f, a, b, key)
		client = e.Client
		encoded = e.AStar
	}
	k := c.KeyGen(bfvpack.Capability{Rotations: rots})
	var ea bfvpack.Cipher
	res.Encrypt = ph(func() { ea = k.Encrypt(encoded, bfvpack.MakeLayout(n+extra, d, n, D)) })
	var out bfvpack.Cipher
	k.Count = &bfvpack.Counts{}
	res.Server = ph(func() { out = k.PublicRightMatmul(ea, b, ell) })
	res.ServerAdds, res.ServerMulPt, res.ServerMulCt, res.ServerRot = k.Count.Add, k.Count.MulPt, k.Count.MulCt, k.Count.Rotate
	var o matrix.Mat
	res.Decrypt = ph(func() { o = k.Decrypt(out) })
	res.Exact = o.TopRows(n).Equal(matrix.Mul(f, a, b))
	if config == "bfv_only" {
		res.Accepted = res.Exact
	} else {
		mode := dataseal.Original
		if config == "dataseal_strengthened" {
			mode = dataseal.Strengthened
		}
		res.Verify = ph(func() { res.Accepted = dataseal.MatmulVerify(f, client, o, mode).Accepted() })
	}
	return res
}

type elemResult struct {
	Config   string `json:"config"`
	Op       string `json:"op"`
	N        int    `json:"logical_elems"`
	Accepted bool   `json:"accepted"`
	Exact    bool   `json:"exact"`
	Server   phase  `json:"server_eval"`
	Total    phase  `json:"client_total"`
	Note     string `json:"note,omitempty"`
}

func main() {
	outDir := "results/lattigo"
	if len(os.Args) == 2 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0o755)
	runtime.GOMAXPROCS(1)

	ctx := bfvpack.NewContext()
	f := ctx.Field()

	// ---- Matmul: controlled vs native packing ----
	type cell struct{ n, d, ell int }
	cells := []cell{{4, 4, 4}, {8, 8, 8}, {16, 16, 16}, {8, 4, 6}}
	configs := []string{"bfv_only", "dataseal_original", "dataseal_strengthened", "private_sketch"}
	groups := map[string][]map[string]interface{}{}
	for _, grp := range []string{"controlled", "native"} {
		var rows []map[string]interface{}
		for _, cl := range cells {
			cD := maxi(cl.n+2, cl.d, cl.ell)
			var results []matmulResult
			for _, cfg := range configs {
				extra := 0
				if cfg == "dataseal_original" || cfg == "dataseal_strengthened" {
					extra = 2
				}
				D := cD
				if grp == "native" {
					D = maxi(cl.n+extra, cl.d, cl.ell)
				}
				results = append(results, benchMatmul(ctx, cfg, cl.n, cl.d, cl.ell, D))
			}
			rows = append(rows, map[string]interface{}{"n": cl.n, "d": cl.d, "ell": cl.ell, "results": results})
		}
		groups[grp] = rows
	}
	writeJSON(outDir+"/matmul.json", map[string]interface{}{
		"packing": "row_major", "warmup": warmup, "trials": trials,
		"gomaxprocs": 1, "groups": groups,
	})

	// ---- Elementwise add/square: bfv_only vs dataseal vs VERITAS REP/PE ----
	rep := veritas.NewRep(bfv.PN13QP218, 4)
	pe := veritas.NewPe(bfv.PN13QP218)
	var elems []elemResult
	nElem := 8
	a := rnd(f, nElem, 1, 5).Col(0)
	b := rnd(f, nElem, 1, 6).Col(0)
	av := matrix.FromInts(f, toRows(a))
	bv := matrix.FromInts(f, toRows(b))

	// bfv_only addition / square via bfvpack (row-major single column)
	kBfv := ctx.KeyGen(bfvpack.Capability{Relin: true})
	layo := bfvpack.MakeLayout(nElem, 1, nElem, nElem)
	elems = append(elems, elemTimed("bfv_only", "add", nElem, func() (bool, bool) {
		ea := kBfv.Encrypt(av, layo)
		eb := kBfv.Encrypt(bv, layo)
		out := kBfv.Decrypt(kBfv.Add(ea, eb))
		return out.Equal(matrix.Add(f, av, bv)), true
	}))
	elems = append(elems, elemTimed("bfv_only", "square", nElem, func() (bool, bool) {
		ea := kBfv.Encrypt(av, layo)
		out := kBfv.Decrypt(kBfv.Square(ea))
		return out.Equal(matrix.Square(f, av)), true
	}))
	elems = append(elems, elemTimed("veritas_rep", "add", nElem, func() (bool, bool) {
		out, ok := rep.Add(a, b)
		return eqslice(out, addv(f, a, b), nElem), ok
	}))
	elems = append(elems, elemTimed("veritas_rep", "square", nElem, func() (bool, bool) {
		out, ok := rep.Square(a)
		return eqslice(out, sqv(f, a), nElem), ok
	}))
	elems = append(elems, elemTimed("veritas_pe", "add", nElem, func() (bool, bool) {
		out, ok := pe.Add(a, b)
		return eqslice(out, addv(f, a, b), nElem), ok
	}))
	elems = append(elems, elemTimed("veritas_pe", "square", nElem, func() (bool, bool) {
		out, ok := pe.Square(a)
		return eqslice(out, sqv(f, a), nElem), ok
	}))
	writeJSON(outDir+"/elementwise.json", map[string]interface{}{
		"note":    "REP/PE use native BFV params (PN13QP218); bfv_only uses PN14QP438 row-major. Not an equal-parameter absolute comparison; see comparability matrix.",
		"results": elems,
	})

	// ---- private-sketch verify r-sweep ----
	var sweep []map[string]interface{}
	n, ell := 16, 16
	A := rnd(f, n, 16, 7)
	B := rnd(f, 16, ell, 8)
	C := matrix.Mul(f, A, B)
	for _, r := range []int{1, 2, 5, 10, 20} {
		cs := sketch.Client{K: sketch.RandomMat(f, r, n), Regs: map[string]sketch.Registration{}}
		sv := sketch.NewServer()
		sketch.Register(f, &cs, &sv, "A", A)
		prog := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: B}}
		tp := sketch.Prepare(f, cs, prog)
		m, q := timeit(func() { _ = sketch.Verify(f, cs, tp, C) })
		sweep = append(sweep, map[string]interface{}{"verify_rows_r": r, "verify_ms": m, "iqr_ms": q})
	}
	writeJSON(outDir+"/sketch_r_sweep.json", map[string]interface{}{"n": n, "ell": ell, "sweep": sweep})

	fmt.Println("wrote", outDir)
}

func elemTimed(config, op string, n int, run func() (bool, bool)) elemResult {
	var exact, acc bool
	m, q := timeit(func() { exact, acc = run() })
	return elemResult{Config: config, Op: op, N: n, Accepted: acc, Exact: exact, Total: phase{m, q}}
}

func toRows(v []uint64) [][]int64 {
	r := make([][]int64, len(v))
	for i, x := range v {
		r[i] = []int64{int64(x)}
	}
	return r
}
func addv(f field.Field, a, b []uint64) []uint64 {
	o := make([]uint64, len(a))
	for i := range a {
		o[i] = f.Add(a[i], b[i])
	}
	return o
}
func sqv(f field.Field, a []uint64) []uint64 {
	o := make([]uint64, len(a))
	for i := range a {
		o[i] = f.Mul(a[i], a[i])
	}
	return o
}
func eqslice(a, b []uint64, n int) bool {
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func maxi(xs ...int) int {
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}
func writeJSON(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}
