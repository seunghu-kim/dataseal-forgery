package main

// Elementwise, input-reuse and composition workloads on the same S1..S9 boundary
// as matmul.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
	"dsfgo/veritas"
)

func digest(x interface{}) string {
	b, _ := json.Marshal(x)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// timedDirect times the client's plaintext computation before t0.
func timedDirect(r bRecord, freq int64, method string, fn func()) {
	t0 := qpcTicks()
	fn()
	t1 := qpcTicks()
	ns := ticksToNs(t1-t0, freq)
	r["direct_computation_ns"], r["direct_computation_time_ns"] = ns, ns
	r["direct_computation_ticks"] = bRecord{"begin": t0, "end": t1, "duration": t1 - t0}
	r["direct_computation_method"] = method + "; one call, no repetition; QPC before t0, outside S1..S9; same result is the correctness reference"
}

func expectUnsupported(r bRecord, reason string) {
	r["execution_status"] = "unsupported_configuration"
	r["error_message"] = reason
	r["unsupported_expected"] = true
}

func newVeritas(method string, peT uint64) (veritas.Scheme, *veritas.Rep, *veritas.Pe) {
	_, lit := profileFor(method, peT)
	if method == "veritas_rep" {
		rep, err := veritas.NewRepParams(lit, repLambda)
		if err != nil {
			panic(err)
		}
		return rep, rep, nil
	}
	pe, err := veritas.NewPeParams(lit)
	if err != nil {
		panic(err)
	}
	return pe, nil, pe
}

func mod17(m matrix.Mat) matrix.Mat {
	out := matrix.New(m.Rows(), m.Cols())
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			out.Set(i, j, m.At(i, j)%65537)
		}
	}
	return out
}

// Elementwise add / square.

func runElement(r bRecord, tm *stageTimer, freq int64, method, op string, n int, seed, peT uint64) {
	r["workload"] = "elementwise_" + op
	r["input_dimensions"] = bRecord{"n": n, "d": 1, "ell": 1}
	r["workload_definition"] = bRecord{"expression": map[string]string{"add": "A[n,1]+D[n,1] mod 65537; A, D confidential", "square": "A[n,1] hadamard A[n,1] mod 65537; A confidential"}[op], "input_sampling": "fixed LCG A=seed, D=seed+1 (rnd)", "input_reuse": "none; fresh session per trial"}
	r["required_rotation_keys"], r["required_relinearization_key"] = []int{}, op == "square"
	r["key_profile_note"] = map[string]string{"add": "no evaluation keys needed or generated", "square": "relinearisation key generated: required by ct x ct squaring for every method (exception to the matmul rotation-keys-only rule)"}[op]
	if method == "private_sketch" {
		r["sketch_p"], r["sketch_r"], r["sketch_Q_auth"] = 65537, 10, uint64(1<<32)
	}
	if method == "private_sketch" && op == "square" {
		expectUnsupported(r, "existing private-sketch Program supports linear Input/MulRight/AddInput/AddConst only; no authenticated nonlinear squaring")
		return
	}
	f := field.New(65537)
	a, d := rnd(f, n, 1, seed), rnd(f, n, 1, seed+1)
	var want matrix.Mat
	timedDirect(r, freq, map[string]string{"add": "matrix.Add(field 65537)", "square": "matrix.Square(field 65537)"}[op], func() {
		if op == "add" {
			want = matrix.Add(f, a, d)
		} else {
			want = matrix.Square(f, a)
		}
	})
	if veritasMethods[method] {
		r["packing_strategy"] = "official_logical_vector_single_ct"
		r["packing_stride"] = 1
		r["input_dimensions"].(bRecord)["padded_dim"] = 1
		var s veritas.Scheme
		var rep *veritas.Rep
		var pe *veritas.Pe
		tm.stage("context_setup", func() { s, rep, pe = newVeritas(method, peT) })
		tm.stage("session_key_generation", func() {
			if rep != nil {
				rep.KeyGenRelin(nil, op == "square", tm.hook)
			} else {
				pe.KeyGenRelin(nil, op == "square", tm.hook)
			}
		})
		tm.skip("authentication_preparation", "VERITAS: authentication keys inside official GenSecretKey (S2); input authentication state in S5")
		tm.skip("public_program_preparation", "no public operand in elementwise add/square")
		var ia, id veritas.ElementInput
		tm.stage("input_encode_encrypt", func() {
			ia = veritas.EncryptVector(s, a.Col(0), tm.hook)
			if op == "add" {
				id = veritas.EncryptVector(s, d.Col(0), tm.hook)
			}
		})
		var res veritas.ElementResult
		tm.stage("server_evaluation", func() { res = veritas.ElementServer(s, op, ia, id) })
		tm.stage("verifier_precomputation", func() { veritas.ElementVerifier(s, op, ia, id, &res) })
		tm.stage("decryption", func() { veritas.ElementDecrypt(s, &res) })
		var vals []uint64
		var verr error
		tm.stage("verification_decode", func() { vals, verr = veritas.ElementVerify(s, res, n) })
		r["accepted"] = verr == nil
		if op == "add" {
			r["addition_count"], r["ciphertext_multiplication_count"], r["relinearization_count"] = 1, 0, 0
		} else {
			r["addition_count"], r["ciphertext_multiplication_count"], r["relinearization_count"] = 0, 1, 1
		}
		r["rotation_count"], r["plaintext_multiplication_count"] = 0, 0
		r["operation_count_source"] = "analytical"
		r["operation_count_scope"] = "official server API calls of the elementwise circuit"
		if rep != nil {
			r["relinearization_key_available"] = rep.RelinKeyPresent()
		} else {
			r["relinearization_key_available"] = pe.RelinKeyPresent()
		}
		in, out := veritas.ElementBytes(res, ia)
		if op == "add" {
			in, out = veritas.ElementBytes(res, ia, id)
		}
		r["input_ct_bytes"], r["output_ct_bytes"] = in, out
		if verr != nil {
			r["verification_errors"] = []string{verr.Error()}
			r["actual_output_note"] = "official decode did not return a verified plaintext"
			return
		}
		got := matrix.New(n, 1)
		for i := 0; i < n; i++ {
			got.Set(i, 0, vals[i]%65537)
		}
		outputs(r, want, got)
		return
	}
	// BFV-based methods (stride n+1, single ciphertext)
	extra := 0
	if strings.HasPrefix(method, "dataseal_") {
		extra = 1
		r["verifier"] = map[string]string{"add": "dataseal_add", "square": "dataseal_corrected_square"}[op]
		r["variant_note"] = "Original/Strengthened distinction belongs to MatmulVerify; the existing dedicated AddVerify/SquareVerify is used for both"
	}
	dim := n + 1
	r["packing_strategy"] = "common_stride_n_plus_1_single_ct"
	r["packing_stride"] = dim
	r["input_dimensions"].(bRecord)["padded_dim"] = dim
	var ctx bfvpack.Context
	tm.stage("context_setup", func() { ctx = bfvpack.NewContext() })
	var keys bfvpack.Keys
	tm.stage("session_key_generation", func() { keys = ctx.KeyGen(bfvpack.Capability{Relin: op == "square"}) })
	encA, encD := a, d
	var addClient dataseal.AddClient
	var sqClient dataseal.SquareClient
	var cs sketch.Client
	var target matrix.Mat
	switch {
	case extra > 0:
		tm.stage("authentication_preparation", func() {
			tm.hook("authentication_encode_and_program", func() {
				if op == "add" {
					e := dataseal.AddEncode(f, a, d, rnd(f, n, 1, 3).Col(0))
					encA, encD, addClient = e.AStar, e.BStar, e.Client
				} else {
					e := dataseal.SquareEncode(f, a, []uint64{7})
					encA, sqClient = e.AStar, e.Client
				}
			})
		})
	case method == "private_sketch":
		tm.stage("authentication_preparation", func() {
			tm.hook("authentication_key_generation", func() { cs = sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n) })
			tm.hook("authentication_registration", func() {
				sv := sketch.NewServer()
				sketch.Register(f, &cs, &sv, "A", a)
				sketch.Register(f, &cs, &sv, "D", d)
			})
			tm.hook("authentication_program_preparation", func() {
				target = sketch.Prepare(f, cs, sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.AddInput, Label: "D"}})
			})
		})
	default:
		tm.skip("authentication_preparation", "unauthenticated baseline")
	}
	tm.skip("public_program_preparation", "no public operand in elementwise add/square")
	layout := bfvpack.MakeLayout(n+extra, 1, n, dim)
	var ea, ed, out bfvpack.Cipher
	tm.stage("input_encode_encrypt", func() {
		ea = keys.Encrypt(encA, layout)
		if op == "add" {
			ed = keys.Encrypt(encD, layout)
		}
	})
	tm.stage("server_evaluation", func() {
		if op == "add" {
			out = keys.Add(ea, ed)
		} else {
			out = keys.Square(ea)
		}
	})
	tm.skip("verifier_precomputation", "no post-evaluation verifier precomputation")
	var got matrix.Mat
	tm.stage("decryption", func() { got = keys.Decrypt(out) })
	switch {
	case extra > 0:
		tm.stage("verification_decode", func() {
			var res dataseal.VerifyResult
			if op == "add" {
				res = dataseal.AddVerify(f, addClient, got)
			} else {
				res = dataseal.SquareVerify(f, sqClient, got)
			}
			r["accepted"], r["verifier_checks"] = res.Accepted(), res.Checks
		})
	case method == "private_sketch":
		tm.stage("verification_decode", func() { r["accepted"] = sketch.Verify(f, cs, target, got) })
	default:
		tm.skip("verification_decode", "unauthenticated baseline: no verification")
	}
	c := keys.CountSnapshot()
	r["rotation_count"], r["plaintext_multiplication_count"], r["ciphertext_multiplication_count"], r["addition_count"] = c.Rotate, c.MulPt, c.MulCt, c.Add
	r["relinearization_count"] = map[string]int{"add": 0, "square": 1}[op]
	r["operation_count_source"] = "measured"
	r["operation_count_scope"] = "completed bfvpack evaluator API calls; Square includes relinearisation"
	r["relinearization_key_available"] = keys.AvailableEvaluationKeys().Relin
	size := ea.Bytes()
	if op == "add" {
		size += ed.Bytes()
	}
	r["input_ct_bytes"], r["output_ct_bytes"], r["eval_key_bytes"] = size, out.Bytes(), keys.EvalKeyBytes()
	outputs(r, want, got.TopRows(n))
}

// Input reuse.

type programOutcome struct {
	accepted *bool
	got      matrix.Mat
}

func finishReuse(r bRecord, wants []matrix.Mat, res []programOutcome, seeds []uint64, bs []matrix.Mat) {
	list := []bRecord{}
	anyWrong, allAcc, accKnown, maxErr := false, true, true, uint64(0)
	for j := range wants {
		pr := bRecord{"program_index": j, "public_seed": seeds[j], "public_matrix_sha256": digest(rows(bs[j]))}
		if res[j].accepted != nil {
			pr["accepted"] = *res[j].accepted
			allAcc = allAcc && *res[j].accepted
		} else {
			accKnown = false
		}
		if res[j].accepted != nil && !*res[j].accepted && res[j].got.Rows() == 0 {
			pr["wrong_output"] = bMissing
		} else {
			sub := bRecord{}
			outputs(sub, wants[j], res[j].got)
			pr["wrong_output"], pr["error_magnitude"] = sub["wrong_output"], sub["error_magnitude"]
			anyWrong = anyWrong || sub["wrong_output"] == true
			if e, ok := sub["error_magnitude"].(uint64); ok && e > maxErr {
				maxErr = e
			}
		}
		list = append(list, pr)
	}
	r["program_results"] = list
	r["wrong_output"], r["error_magnitude"] = anyWrong, maxErr
	r["error_magnitude_definition"] = "max over programs of max centered modular absolute difference"
	if accKnown {
		r["accepted"] = allAcc
		r["attack_success"] = anyWrong && allAcc
	}
	r["all_programs_correct"] = !anyWrong
}

func runReuse(r bRecord, tm *stageTimer, freq int64, method, packing string, n, k int, seed, peT uint64) {
	f := field.New(65537)
	a := rnd(f, n, n, seed)
	bs, seeds, wants := make([]matrix.Mat, k), make([]uint64, k), make([]matrix.Mat, k)
	for j := 0; j < k; j++ {
		seeds[j] = seed + 1 + uint64(j)
		bs[j] = rnd(f, n, n, seeds[j])
	}
	r["workload"] = "input_reuse_public_right_matmul"
	r["input_reuse_programs"], r["programs_per_trial"] = k, k
	r["reuse_policy"] = "one_ciphertext_multiple_distinct_public_programs"
	r["program_family_id"] = "seeded-distinct-public-matrices-prefix-family-v1"
	r["workload_definition"] = bRecord{"expression": "C_j = A*B_j mod 65537, j=0..k-1; one encrypted A, distinct public B_j", "input_seed": seed, "public_seeds": "seed+1+j", "independent_input": false}
	timedDirect(r, freq, fmt.Sprintf("%d calls of matrix.Mul(field 65537), one per program (total reported)", k), func() {
		for j := 0; j < k; j++ {
			wants[j] = matrix.Mul(f, a, bs[j])
		}
	})
	res := make([]programOutcome, k)
	if veritasMethods[method] {
		block := peBlock
		if method == "veritas_rep" {
			block = repBlock
		}
		g := veritas.NewGeometry(n, n, n, block)
		r["packing_strategy"] = "native_single_ct"
		if g.IBlocks()*g.KBlocks() > 1 {
			r["packing_strategy"] = "native_tiled"
			r["tiling_note"] = fmt.Sprintf("%dx%d input tiles of block %d (stride = block)", g.IBlocks(), g.KBlocks(), g.Block)
		}
		r["packing_stride"], r["block_size"] = g.Dim, g.Block
		r["input_dimensions"].(bRecord)["padded_dim"] = g.Dim
		r["required_rotation_keys"], r["required_relinearization_key"] = g.Rotations(), false
		r["program_sharing"] = "each program prepared once; (k,j) masks shared across row blocks (public data reuse)"
		r["public_mask"] = maskNote
		var s veritas.Scheme
		var rep *veritas.Rep
		var pe *veritas.Pe
		tm.stage("context_setup", func() { s, rep, pe = newVeritas(method, peT) })
		tm.stage("session_key_generation", func() {
			if rep != nil {
				rep.KeyGen(g.Rotations(), tm.hook)
			} else {
				pe.KeyGen(g.Rotations(), tm.hook)
			}
		})
		tm.skip("authentication_preparation", "VERITAS: authentication keys inside official GenSecretKey (S2); input authentication state in S5; M4 public masks carry none")
		progs := make([]veritas.Program, k)
		tm.stage("public_program_preparation", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { progs[j] = veritas.Prepare(s, g, bs[j]) })
			}
		})
		var in veritas.Input
		tm.stage("input_encode_encrypt", func() { in = veritas.Encrypt(s, g, a, tm.hook) })
		outs := make([]veritas.Output, k)
		tm.stage("server_evaluation", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { outs[j] = veritas.Server(s, in, progs[j]) })
			}
		})
		vers := make([]veritas.Verif, k)
		tm.stage("verifier_precomputation", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { vers[j] = veritas.Verifier(s, in, progs[j]) })
			}
		})
		decs := make([]veritas.Decrypted, k)
		tm.stage("decryption", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { decs[j] = veritas.Decrypt(s, outs[j]) })
			}
		})
		results := make([]veritas.Result, k)
		tm.stage("verification_decode", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() {
					results[j] = veritas.Verify(s, decs[j], vers[j])
					if results[j].Accepted {
						results[j].Out = mod17(results[j].Out)
					}
				})
			}
		})
		ops := veritas.ProgramOps{}
		for j := 0; j < k; j++ {
			acc := results[j].Accepted
			res[j] = programOutcome{accepted: &acc, got: results[j].Out}
			if !acc {
				res[j].got = matrix.Mat{}
			}
			ops.Rotate += progs[j].Ops.Rotate
			ops.MulPt += progs[j].Ops.MulPt
			ops.Add += progs[j].Ops.Add
		}
		r["rotation_count"], r["plaintext_multiplication_count"], r["addition_count"], r["ciphertext_multiplication_count"] = ops.Rotate, ops.MulPt, ops.Add, 0
		r["operation_count_source"] = "analytical"
		r["operation_count_scope"] = "sum over programs of official API calls derived from the prepared programs"
		r["input_tiles"] = in.NumTiles()
		r["input_ct_bytes"] = veritas.CiphertextBytes(in.InputCiphertexts())
		finishReuse(r, wants, res, seeds, bs)
		return
	}
	g := bfvGeometry(method, packing, n)
	if g.tiled {
		panic("reuse is limited to single-ciphertext sizes")
	}
	r["packing_strategy"] = packing + "_single_ct"
	r["packing_stride"] = g.dim
	r["input_dimensions"].(bRecord)["padded_dim"] = g.dim
	r["required_rotation_keys"], r["required_relinearization_key"] = g.rots, false
	r["program_sharing"] = "each program prepared once (single ciphertext)"
	var ctx bfvpack.Context
	tm.stage("context_setup", func() { ctx = bfvpack.NewContext() })
	var keys bfvpack.Keys
	tm.stage("session_key_generation", func() { keys = ctx.KeyGen(bfvpack.Capability{Rotations: g.rots}) })
	encoded := a
	dsc := make([]dataseal.MatmulClient, k)
	var cs sketch.Client
	targets := make([]matrix.Mat, k)
	switch {
	case g.extra > 0:
		tm.stage("authentication_preparation", func() {
			key := dataseal.MatmulKey{}
			var w, gg []uint64
			tm.hook("authentication_key_generation", func() { key = dataseal.MatmulKey{K: rnd(f, n, 1, 3).Col(0), Alpha: 7} })
			tm.hook("authentication_registration", func() { w, gg = dataseal.MatmulInputChecksum(f, a, key); encoded = a.AppendRows(w, gg) })
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("authentication_program_preparation_%d", j), func() {
					u0, z := dataseal.MatmulExpected(f, bs[j], w, gg)
					dsc[j] = dataseal.MatmulClient{Key: key, N: n, D: n, Ell: n, W: w, G: gg, U0: u0, Z: z}
				})
			}
		})
	case method == "private_sketch":
		r["sketch_p"], r["sketch_r"], r["sketch_Q_auth"] = 65537, 10, uint64(1<<32)
		tm.stage("authentication_preparation", func() {
			tm.hook("authentication_key_generation", func() { cs = sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n) })
			tm.hook("authentication_registration", func() { sv := sketch.NewServer(); sketch.Register(f, &cs, &sv, "A", a) })
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("authentication_program_preparation_%d", j), func() {
					targets[j] = sketch.Prepare(f, cs, sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: bs[j]}})
				})
			}
		})
	default:
		tm.skip("authentication_preparation", "unauthenticated baseline")
	}
	layout := bfvpack.MakeLayout(n+g.extra, n, n, g.dim)
	preps := make([]bfvpack.PreparedMatmul, k)
	tm.stage("public_program_preparation", func() {
		for j := 0; j < k; j++ {
			tm.hook(fmt.Sprintf("program_%d", j), func() { preps[j] = keys.PrepareMatmul(layout, bs[j], n) })
		}
	})
	var in bfvpack.Cipher
	tm.stage("input_encode_encrypt", func() { in = keys.Encrypt(encoded, layout) })
	outs := make([]bfvpack.Cipher, k)
	tm.stage("server_evaluation", func() {
		for j := 0; j < k; j++ {
			tm.hook(fmt.Sprintf("program_%d", j), func() { outs[j] = keys.ServerMatmul(in, preps[j]) })
		}
	})
	tm.skip("verifier_precomputation", "no post-evaluation verifier precomputation")
	gots := make([]matrix.Mat, k)
	tm.stage("decryption", func() {
		for j := 0; j < k; j++ {
			tm.hook(fmt.Sprintf("program_%d", j), func() { gots[j] = keys.Decrypt(outs[j]) })
		}
	})
	accs := make([]bool, k)
	switch {
	case g.extra > 0:
		mode := dataseal.Original
		if method == "dataseal_strengthened" {
			mode = dataseal.Corrected
		}
		tm.stage("verification_decode", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { accs[j] = dataseal.MatmulVerify(f, dsc[j], gots[j], mode).Accepted() })
			}
		})
	case method == "private_sketch":
		tm.stage("verification_decode", func() {
			for j := 0; j < k; j++ {
				tm.hook(fmt.Sprintf("program_%d", j), func() { accs[j] = sketch.Verify(f, cs, targets[j], gots[j].TopRows(n)) })
			}
		})
	default:
		tm.skip("verification_decode", "unauthenticated baseline: no verification")
	}
	for j := 0; j < k; j++ {
		res[j] = programOutcome{got: gots[j].TopRows(n)}
		if method != "bfv_only" {
			acc := accs[j]
			res[j].accepted = &acc
		}
	}
	c := keys.CountSnapshot()
	r["rotation_count"], r["plaintext_multiplication_count"], r["ciphertext_multiplication_count"], r["addition_count"] = c.Rotate, c.MulPt, c.MulCt, c.Add
	r["operation_count_source"] = "measured"
	r["operation_count_scope"] = "completed bfvpack evaluator API calls summed over all programs (server_evaluation only)"
	r["input_tiles"], r["input_ct_bytes"], r["eval_key_bytes"] = 1, in.Bytes(), keys.EvalKeyBytes()
	finishReuse(r, wants, res, seeds, bs)
}

// Composition.

const sketchCompositionCheck = "sketch check K*Y == (W_A*B1 + W_D)*B2 with W_X = K*X (sketch.Prepare/Verify). Transposed, Y^T K^T = B2^T (B1^T W_A^T + W_D^T): the paper form (Y')^T K = D^T (B^T W_A + W_H) with paper D = our B2 (public), paper B = our B1 (public), paper H = our D (confidential, encrypted, registered input)."

func runCompose(r bRecord, tm *stageTimer, freq int64, method string, n int, seed uint64) {
	r["workload"] = "composition_matmul_add_matmul"
	r["workload_definition"] = bRecord{"expression": "(A*B1 + D)*B2 mod 65537; A, D confidential (encrypted); B1, B2 public", "input_sampling": "fixed LCG A=seed, B1=seed+1, D=seed+2, B2=seed+3"}
	r["added_matrix_D"] = "confidential encrypted input (second ciphertext), not a public matrix; registered as sketch input W_D"
	switch {
	case strings.HasPrefix(method, "dataseal_"):
		expectUnsupported(r, "existing DataSeal API has no composed workload state: MatmulEncode/MatmulVerify are single-matmul (two checksum rows) and AddEncode uses one; no composition rule introduced")
		return
	case veritasMethods[method]:
		expectUnsupported(r, "VERITAS composition not implemented for this comparison (kept unsupported by decision)")
		return
	}
	f := field.New(65537)
	a, b1, d, b2 := rnd(f, n, n, seed), rnd(f, n, n, seed+1), rnd(f, n, n, seed+2), rnd(f, n, n, seed+3)
	var want matrix.Mat
	timedDirect(r, freq, "matrix.Mul, matrix.Add, matrix.Mul (field 65537)", func() { want = matrix.Mul(f, matrix.Add(f, matrix.Mul(f, a, b1), d), b2) })
	dim := n
	rots := bfvpack.PublicMatmulRotations(n, n)
	r["packing_strategy"] = "native_single_ct_shared_layout"
	r["packing_stride"] = dim
	r["input_dimensions"].(bRecord)["padded_dim"] = dim
	r["required_rotation_keys"], r["required_relinearization_key"] = rots, false
	var ctx bfvpack.Context
	tm.stage("context_setup", func() { ctx = bfvpack.NewContext() })
	var keys bfvpack.Keys
	tm.stage("session_key_generation", func() { keys = ctx.KeyGen(bfvpack.Capability{Rotations: rots}) })
	var cs sketch.Client
	var target matrix.Mat
	if method == "private_sketch" {
		r["sketch_p"], r["sketch_r"], r["sketch_Q_auth"] = 65537, 10, uint64(1<<32)
		r["sketch_composition_check"] = sketchCompositionCheck
		tm.stage("authentication_preparation", func() {
			tm.hook("authentication_key_generation", func() { cs = sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n) })
			tm.hook("authentication_registration", func() {
				sv := sketch.NewServer()
				sketch.Register(f, &cs, &sv, "A", a)
				sketch.Register(f, &cs, &sv, "D", d)
			})
			tm.hook("authentication_program_preparation", func() {
				target = sketch.Prepare(f, cs, sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b1}, {Kind: sketch.AddInput, Label: "D"}, {Kind: sketch.MulRight, Mat: b2}})
			})
		})
	} else {
		tm.skip("authentication_preparation", "unauthenticated baseline")
	}
	layout := bfvpack.MakeLayout(n, n, n, dim)
	var p1, p2 bfvpack.PreparedMatmul
	tm.stage("public_program_preparation", func() {
		tm.hook("program_B1", func() { p1 = keys.PrepareMatmul(layout, b1, n) })
		tm.hook("program_B2", func() { p2 = keys.PrepareMatmul(layout, b2, n) })
	})
	var ea, ed, out bfvpack.Cipher
	tm.stage("input_encode_encrypt", func() { ea = keys.Encrypt(a, layout); ed = keys.Encrypt(d, layout) })
	tm.stage("server_evaluation", func() { out = composeServer(tm, keys, ea, ed, p1, p2, nil) })
	tm.skip("verifier_precomputation", "no post-evaluation verifier precomputation")
	var got matrix.Mat
	tm.stage("decryption", func() { got = keys.Decrypt(out) })
	if method == "private_sketch" {
		tm.stage("verification_decode", func() { r["accepted"] = sketch.Verify(f, cs, target, got) })
	} else {
		tm.skip("verification_decode", "unauthenticated baseline: no verification")
	}
	c := keys.CountSnapshot()
	r["rotation_count"], r["plaintext_multiplication_count"], r["ciphertext_multiplication_count"], r["addition_count"] = c.Rotate, c.MulPt, c.MulCt, c.Add
	r["operation_count_source"] = "measured"
	r["operation_count_scope"] = "completed bfvpack evaluator API calls across two ServerMatmul and one ciphertext Add"
	r["input_tiles"], r["output_tiles"] = 2, 1
	r["input_ct_bytes"], r["output_ct_bytes"], r["eval_key_bytes"] = ea.Bytes()+ed.Bytes(), out.Bytes(), keys.EvalKeyBytes()
	outputs(r, want, got)
}

// composeServer is the server circuit; tamper (tests only) modifies the
// intermediate A*B1 + D.
func composeServer(tm *stageTimer, keys bfvpack.Keys, ea, ed bfvpack.Cipher, p1, p2 bfvpack.PreparedMatmul, tamper func(bfvpack.Cipher) bfvpack.Cipher) bfvpack.Cipher {
	var ab, sum, out bfvpack.Cipher
	hook := func(name string, fn func()) {
		if tm != nil {
			tm.hook(name, fn)
		} else {
			fn()
		}
	}
	hook("first_matmul", func() { ab = keys.ServerMatmul(ea, p1) })
	hook("secret_input_addition", func() { sum = keys.Add(ab, ed) })
	if tamper != nil {
		sum = tamper(sum)
	}
	hook("second_matmul", func() { out = keys.ServerMatmul(sum, p2) })
	return out
}
