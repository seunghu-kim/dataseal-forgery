package main

import (
	"strings"

	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
	"dsfgo/veritas"
)

// rnd is the fixed LCG fixture generator.
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

// directCompute times the client's plaintext A*B before t0, outside S1..S9; its
// result is also the correctness reference.
func directCompute(r bRecord, f field.Field, a, b matrix.Mat, freq int64) matrix.Mat {
	t0 := qpcTicks()
	want := matrix.Mul(f, a, b)
	t1 := qpcTicks()
	ns := ticksToNs(t1-t0, freq)
	r["direct_computation_ns"] = ns
	r["direct_computation_time_ns"] = ns // same observation under the schema field name
	r["direct_computation_ticks"] = bRecord{"begin": t0, "end": t1, "duration": t1 - t0}
	r["direct_computation_method"] = "one call of dsfgo/matrix.Mul(field 65537, A[n,n], B[n,n]): schoolbook i-k-j triple loop, field.Mul (64-bit mulmod via bits.Mul64/Div64) and field.Add per term, zero A entries skipped; no repetition or batching; timed with QPC before t0, outside S1..S9; the same result is the correctness reference"
	return want
}

func rows(m matrix.Mat) [][]uint64 {
	out := make([][]uint64, m.Rows())
	for i := range out {
		out[i] = append([]uint64{}, m.Row(i)...)
	}
	return out
}

// outputs checks the result against the reference; attack_success = wrong && accepted.
func outputs(r bRecord, want, got matrix.Mat) {
	r["expected_output"], r["actual_output"] = rows(want), rows(got)
	wrong := want.Rows() != got.Rows() || want.Cols() != got.Cols()
	max := uint64(0)
	if !wrong {
		for i := 0; i < got.Rows(); i++ {
			for j := 0; j < got.Cols(); j++ {
				d := (got.At(i, j) + 65537 - want.At(i, j)) % 65537
				wrong = wrong || d != 0
				if d > 65537/2 {
					d = 65537 - d
				}
				if d > max {
					max = d
				}
			}
		}
		r["error_magnitude"] = max
		r["error_magnitude_definition"] = "max centered modular absolute difference"
	}
	r["wrong_output"] = wrong
	if a, ok := r["accepted"].(bool); ok {
		r["attack_success"] = wrong && a
	}
}

// bfvGeo is the packing geometry (stride, tiling, rotations) of a BFV-based method.
type bfvGeo struct {
	extra, dim int
	tiled      bool
	layout     bfvpack.TiledLayout
	rots       []int
	plan       bfvpack.MatmulPlan
}

func bfvGeometry(method, packing string, n int) bfvGeo {
	g := bfvGeo{}
	if strings.HasPrefix(method, "dataseal_") {
		g.extra = 2
	}
	g.plan = bfvpack.PlanMatmul(method, n, n, n, g.extra, tileCol, "PN14QP438")
	g.tiled = g.plan.Strategy == bfvpack.StrategyTiled
	g.dim = g.plan.SingleCtDim
	if g.tiled {
		g.dim = tileCol + g.extra
		if packing == "controlled" {
			g.dim = tileCol + 2
		}
		g.layout = bfvpack.NewTiledLayout(n+g.extra, n, n, tileCol, g.dim, g.extra > 0)
		g.rots = bfvpack.TiledMatmulRotations(n, n, tileCol)
	} else {
		if packing == "controlled" {
			g.dim = n + 2
		}
		g.rots = bfvpack.PublicMatmulRotations(n, n)
	}
	return g
}

// runBFV runs one trial of a BFV-based method. sketchRows 0 uses
// sketch.RowsFor(65537,128,2^32); a positive value overrides it (cost comparison).
func runBFV(r bRecord, tm *stageTimer, freq int64, method, packing string, n int, seed uint64, sketchRows int) {
	f := field.New(65537)
	a, b := rnd(f, n, n, seed), rnd(f, n, n, seed+1)
	want := directCompute(r, f, a, b, freq)
	g := bfvGeometry(method, packing, n)
	r["matmul_plan"] = g.plan
	r["packing_stride"] = g.dim
	if g.tiled {
		r["packing_strategy"] = packing + "_tiled"
		r["tile_layout"] = g.layout
	} else {
		r["packing_strategy"] = packing + "_single_ct"
		r["tile_layout"] = bRecord{"rows": n + g.extra, "cols": n, "stride": g.dim, "row_offsets": []int{0, n + g.extra}, "col_offsets": []int{0, n}}
	}
	r["input_dimensions"].(bRecord)["padded_dim"] = g.dim
	r["required_rotation_keys"] = g.rots
	r["required_relinearization_key"] = false
	r["program_sharing"] = "per_row_block (B-2 PrepareTiledMatmul structure)"
	usedRows := sketchRowsUsed(sketchRows) // recorded value only; computed before t0

	// t0
	var ctx bfvpack.Context
	tm.stage("context_setup", func() { ctx = bfvpack.NewContext() })
	var k bfvpack.Keys
	tm.stage("session_key_generation", func() { k = ctx.KeyGen(bfvpack.Capability{Rotations: g.rots}) })
	encoded := a
	var ds dataseal.MatmulClient
	var sk sketch.Client
	var target matrix.Mat
	switch {
	case g.extra > 0:
		tm.stage("authentication_preparation", func() {
			var key dataseal.MatmulKey
			tm.hook("authentication_key_generation", func() { key = dataseal.MatmulKey{K: rnd(f, n, 1, 3).Col(0), Alpha: 7} })
			tm.hook("authentication_encode_and_program", func() { e := dataseal.MatmulEncode(f, a, b, key); ds, encoded = e.Client, e.AStar })
		})
	case method == "private_sketch":
		r["sketch_p"], r["sketch_r"], r["sketch_Q_auth"] = 65537, usedRows, uint64(1<<32)
		tm.stage("authentication_preparation", func() {
			if sketchRows > 0 {
				tm.hook("authentication_key_generation", func() { sk = sketch.Keygen(f, sketchRows, n) })
			} else {
				tm.hook("authentication_key_generation", func() { sk = sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n) })
			}
			tm.hook("authentication_registration", func() { sv := sketch.NewServer(); sketch.Register(f, &sk, &sv, "A", a) })
			tm.hook("authentication_program_preparation", func() {
				program := sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b}}
				target = sketch.Prepare(f, sk, program)
			})
		})
	default:
		tm.skip("authentication_preparation", "unauthenticated baseline")
	}
	var prep bfvpack.PreparedMatmul
	var tprep bfvpack.PreparedTiledMatmul
	tm.stage("public_program_preparation", func() {
		if g.tiled {
			tprep = ctx.PrepareTiledMatmul(g.layout, b, n)
		} else {
			prep = k.PrepareMatmul(bfvpack.MakeLayout(n+g.extra, n, n, g.dim), b, n)
		}
	})
	var in, out bfvpack.Cipher
	var ti, to bfvpack.TiledCipher
	tm.stage("input_encode_encrypt", func() {
		if g.tiled {
			ti = k.EncryptTiledLayout(encoded, g.layout)
		} else {
			in = k.Encrypt(encoded, bfvpack.MakeLayout(n+g.extra, n, n, g.dim))
		}
	})
	tm.stage("server_evaluation", func() {
		if g.tiled {
			to = k.ServerTiledMatmul(ti, tprep)
		} else {
			out = k.ServerMatmul(in, prep)
		}
	})
	tm.skip("verifier_precomputation", "no post-evaluation verifier precomputation (DataSeal/sketch expected values prepared in S3)")
	var got matrix.Mat
	tm.stage("decryption", func() {
		if g.tiled {
			got = k.DecryptTiled(to)
		} else {
			got = k.Decrypt(out)
		}
	})
	switch {
	case method == "private_sketch":
		tm.stage("verification_decode", func() { r["accepted"] = sketch.Verify(f, sk, target, got.TopRows(n)) })
	case g.extra > 0:
		mode := dataseal.Original
		if method == "dataseal_strengthened" {
			mode = dataseal.Corrected
		}
		tm.stage("verification_decode", func() {
			res := dataseal.MatmulVerify(f, ds, got, mode)
			r["accepted"] = res.Accepted()
			r["verifier_checks"] = res.Checks
		})
	default:
		tm.skip("verification_decode", "unauthenticated baseline: no verification")
	}
	// t_end (end of the last measured stage); post-processing below
	cs := k.CountSnapshot()
	r["rotation_count"], r["ciphertext_multiplication_count"], r["plaintext_multiplication_count"], r["addition_count"] = cs.Rotate, cs.MulCt, cs.MulPt, cs.Add
	r["operation_count_source"] = "measured"
	r["operation_count_scope"] = "completed bfvpack evaluator API calls during server_evaluation (no other stage increments the counters); snapshot taken after t_end"
	if g.tiled {
		r["input_ct_bytes"], r["output_ct_bytes"], r["input_tiles"], r["output_tiles"] = ti.Bytes(), to.Bytes(), ti.NumTiles(), to.NumTiles()
	} else {
		r["input_ct_bytes"], r["output_ct_bytes"], r["input_tiles"], r["output_tiles"] = in.Bytes(), out.Bytes(), 1, 1
	}
	r["eval_key_bytes"] = k.EvalKeyBytes()
	if method == "private_sketch" {
		for key, v := range sketchBoundFields(sketchRows) {
			r[key] = v
		}
		r["sketch_K_rows"] = sk.K.Rows() // actual key shape, after t_end
	}
	outputs(r, want, got.TopRows(n))
}

// runVeritas runs one trial for REP or PE with public masks.
func runVeritas(r bRecord, tm *stageTimer, freq int64, method string, n int, seed, peT uint64) {
	f := field.New(65537)
	a, b := rnd(f, n, n, seed), rnd(f, n, n, seed+1)
	want := directCompute(r, f, a, b, freq)
	block, logical := peBlock, 16384
	if method == "veritas_rep" {
		block, logical = repBlock, 16384/repLambda
	}
	g := veritas.NewGeometry(n, n, n, block)
	if err := g.CheckCapacity(logical); err != nil {
		r["execution_status"] = "unsupported_configuration"
		r["error_message"] = err.Error()
		return
	}
	_, lit := profileFor(method, peT)
	r["packing_strategy"] = "native_single_ct"
	if g.IBlocks()*g.KBlocks() > 1 {
		r["packing_strategy"] = "native_tiled"
	}
	r["packing_stride"] = g.Dim
	r["block_size"] = g.Block
	r["tile_layout"] = bRecord{"rows": n, "cols": n, "stride": g.Dim, "row_offsets": g.RowOff, "inner_offsets": g.InnerOff, "col_offsets": g.OutOff}
	r["input_dimensions"].(bRecord)["padded_dim"] = g.Dim
	r["required_rotation_keys"] = g.Rotations()
	r["required_relinearization_key"] = false
	r["program_sharing"] = "shared_across_row_blocks (public data reuse, same nature as BFV public masks)"
	r["public_mask"] = maskNote
	if method == "veritas_rep" {
		r["replication_lambda"] = repLambda
	}

	// t0
	var s veritas.Scheme
	var rep *veritas.Rep
	var pe *veritas.Pe
	tm.stage("context_setup", func() {
		var err error
		if method == "veritas_rep" {
			rep, err = veritas.NewRepParams(lit, repLambda)
			s = rep
		} else {
			pe, err = veritas.NewPeParams(lit)
			s = pe
		}
		if err != nil {
			panic(err)
		}
	})
	tm.stage("session_key_generation", func() {
		if rep != nil {
			rep.KeyGen(g.Rotations(), tm.hook)
		} else {
			pe.KeyGen(g.Rotations(), tm.hook)
		}
	})
	tm.skip("authentication_preparation", "VERITAS: authentication keys are generated inside the official GenSecretKey (S2); input authentication state is created in S5; M4 public masks carry none")
	var prog veritas.Program
	tm.stage("public_program_preparation", func() { prog = veritas.Prepare(s, g, b) })
	var in veritas.Input
	tm.stage("input_encode_encrypt", func() { in = veritas.Encrypt(s, g, a, tm.hook) })
	var out veritas.Output
	tm.stage("server_evaluation", func() { out = veritas.Server(s, in, prog) })
	var ver veritas.Verif
	tm.stage("verifier_precomputation", func() { ver = veritas.Verifier(s, in, prog) })
	var dec veritas.Decrypted
	tm.stage("decryption", func() { dec = veritas.Decrypt(s, out) })
	var res veritas.Result
	tm.stage("verification_decode", func() {
		res = veritas.Verify(s, dec, ver)
		if lit.T != 65537 && res.Accepted { // decoded integers mod t -> F_65537
			for i := 0; i < n; i++ {
				for j := 0; j < n; j++ {
					res.Out.Set(i, j, res.Out.At(i, j)%65537)
				}
			}
		}
	})
	// t_end; post-processing
	r["accepted"] = res.Accepted
	ops := prog.Ops
	r["rotation_count"], r["plaintext_multiplication_count"], r["addition_count"], r["ciphertext_multiplication_count"] = ops.Rotate, ops.MulPt, ops.Add, 0
	r["operation_count_source"] = "analytical"
	r["operation_count_scope"] = "logical official API calls derived from the prepared program (per tile triple), not low-level BFV component operations"
	r["input_tiles"], r["output_tiles"] = in.NumTiles(), out.NumTiles()
	r["input_ct_bytes"], r["output_ct_bytes"] = veritas.CiphertextBytes(in.InputCiphertexts()), veritas.CiphertextBytes(out.OutputCiphertexts())
	if rep != nil {
		r["eval_key_bytes"] = rep.EvalKeyBytes()
	} else {
		r["eval_key_bytes"] = pe.EvalKeyBytes()
	}
	r["size_boundary"] = "sum of underlying BFV MarshalBinary payloads; REP detached tags and PE container framing excluded"
	if res.Accepted {
		outputs(r, want, res.Out)
	} else {
		r["verification_errors"] = res.Errors
		class := "verifier_rejection"
		for _, e := range res.Errors {
			if !strings.Contains(e, "verification failed") {
				class = "runtime_error_during_decode"
			}
		}
		r["verification_error_class"] = class
		r["actual_output_note"] = "official decode did not return a verified plaintext; no output reported"
	}
}
