package attackrun

import (
	"dsfgo/attacks"
	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/matrix"
)

type prepared struct {
	x                             inputs
	encoded, other, correct, full matrix.Mat
	mc                            dataseal.MatmulClient
	ac                            dataseal.AddClient
	sc                            dataseal.SquareClient
	h                             []uint64
}

func prepare(ctx bfvpack.Context, c Config, t task, r Record) (prepared, error) {
	f := ctx.Field()
	x, e := makeInputs(f, c.Mode, t.Scenario, t.Size, t.Seed)
	if e != nil {
		return prepared{}, e
	}
	p := prepared{x: x}
	r["seed"] = x.Provenance
	r["seed_provenance"] = x.Provenance
	r["input_digest_sha256"] = x.Digest
	r["input_unit_id"] = "input-" + x.Digest
	switch t.Scenario {
	case "selective_scaling", "matmul_kernel":
		e := dataseal.MatmulEncode(f, x.A, x.B, dataseal.MatmulKey{K: x.K, Alpha: 7})
		p.mc = e.Client
		p.encoded = e.AStar
		p.correct = matrix.Mul(f, x.A, x.B)
		p.full = dataseal.MatmulEval(f, e)
	case "addition_kernel":
		e := dataseal.AddEncode(f, x.A, x.B, x.K)
		p.ac = e.Client
		p.encoded, p.other = e.AStar, e.BStar
		p.correct = matrix.Add(f, x.A, x.B)
		p.full = dataseal.AddEval(f, e)
	default:
		e := dataseal.SquareEncode(f, x.A, x.Eta)
		p.sc = e.Client
		p.encoded = e.AStar
		p.correct = matrix.Square(f, x.A)
		p.full = dataseal.SquareEval(f, e)
	}
	r["expected_output"] = rows(p.correct)
	r["expected_augmented_output"] = rows(p.full)
	switch t.Scenario {
	case "matmul_kernel", "addition_kernel":
		var nonzero bool
		var dot uint64
		p.h, nonzero, dot = referenceKernel(f, x, t.Size.N)
		r["mathematical_precondition"] = "h=w_b*A_col_a-w_a*A_col_b is nonzero and k^T*h=0 in F_65537"
		r["precondition_satisfied"] = nonzero && dot == 0
		r["precondition_evidence"] = Record{"h": p.h, "h_nonzero": nonzero, "k_dot_h": dot, "source": "client plaintext mathematical reference, not ciphertext execution"}
	case "selective_scaling":
		nontrivial := false
		for i := 0; i < p.correct.Rows(); i++ {
			for j := 0; j < p.correct.Cols(); j++ {
				nontrivial = nontrivial || p.correct.At(i, j) != 0
			}
		}
		projectionNonzero := false
		for _, v := range p.mc.U0 {
			projectionNonzero = projectionNonzero || v != 0
		}
		r["mathematical_precondition"] = "factor 3 changes correct data output (3*C != C in F_65537)"
		r["precondition_satisfied"] = nontrivial
		r["precondition_evidence"] = Record{"factor": 3, "correct_data_nonzero": nontrivial, "expected_checksum_nonzero": projectionNonzero, "note": "Strengthened rejection is not assumed when expected checksum is zero"}
	case "square_permute":
		v1, v2 := p.correct.At(0, 1), p.correct.At(2, 1)
		r["mathematical_precondition"] = "selected squared entries differ, making the existing permutation nontrivial"
		r["precondition_satisfied"] = v1 != v2
		r["precondition_evidence"] = Record{"row_a": 0, "row_b": 2, "column": 1, "squared_values": []uint64{v1, v2}, "honest_column_products": matrix.ColumnProducts(f, p.correct)}
	case "square_rescale":
		v1, v2 := p.correct.At(0, 1), p.correct.At(2, 1)
		r["mathematical_precondition"] = "gamma=3 is nonzero/nonunit and at least one selected squared entry is nonzero"
		r["precondition_satisfied"] = (v1 != 0 || v2 != 0)
		r["precondition_evidence"] = Record{"gamma": 3, "gamma_inverse": f.Inv(3), "squared_values": []uint64{v1, v2}, "honest_column_products": matrix.ColumnProducts(f, p.correct)}
	}
	return p, nil
}
func checksumEqual(a, b matrix.Mat, n int) bool {
	if a.Rows() != b.Rows() || a.Cols() != b.Cols() {
		return false
	}
	for i := n; i < a.Rows(); i++ {
		for j := 0; j < a.Cols(); j++ {
			if a.At(i, j) != b.At(i, j) {
				return false
			}
		}
	}
	return true
}
func kernelMatches(ctx bfvpack.Context, actual, honest matrix.Mat, h []uint64, target, n int) bool {
	if actual.Rows() != honest.Rows() || actual.Cols() != honest.Cols() {
		return false
	}
	f := ctx.Field()
	for i := 0; i < actual.Rows(); i++ {
		for j := 0; j < actual.Cols(); j++ {
			want := uint64(0)
			if i < n && j == target {
				want = h[i]
			}
			if f.Sub(actual.At(i, j), honest.At(i, j)) != want {
				return false
			}
		}
	}
	return true
}
func runTask(ctx bfvpack.Context, s schema, c Config, t task, machine, metadata string, seen map[string]string, emit func(Record) error) error {
	r := baseRecord(s, c, t, machine, metadata)
	cap, honestRot, attackRot, honestRelin, attackRelin := requirements(t)
	required := unique(append(append([]int{}, honestRot...), attackRot...))
	r["required_rotation_keys"] = required
	r["required_relinearization_key"] = honestRelin || attackRelin
	r["attack_required_rotation_keys"] = attackRot
	r["attack_required_relinearization_key"] = attackRelin
	r["honest_required_rotation_keys"] = honestRot
	r["declared_rotation_keys"] = cap.Rotations
	r["declared_relinearization_key"] = cap.Relin
	r["key_requirement_source"] = "analytical from existing operation sequence and packing geometry; available material assigned only after successful KeyGen"
	r["evaluation_key_material_created"] = false
	r["missing_rotation_keys"] = missingKeys(required, cap.Rotations)
	r["missing_relinearization_key"] = (honestRelin || attackRelin) && !cap.Relin
	if len(missingKeys(required, cap.Rotations)) > 0 || ((honestRelin || attackRelin) && !cap.Relin) {
		r["unsupported_capability_reason"] = "declared profile lacks required key material; this is a capability diagnosis, not an execution-status classification"
	} else {
		r["unsupported_capability_reason"] = Missing
	}
	start := attackNow()
	tm := timer{r: r, now: attackNow}
	var p prepared
	var k bfvpack.Keys
	var in, other, honest, changed bfvpack.Cipher
	var hc, actual matrix.Mat
	var meter *bfvpack.OperationMeter
	var provisioned bfvpack.Capability
	status, msg, stack := guard(func() {
		tm.stage("preparation", func() {
			var e error
			p, e = prepare(ctx, c, t, r)
			if e != nil {
				panic(e)
			}
			unit := t.InputGroup
			digestKey := t.Scenario + ":" + p.x.Digest
			first, exists := seen[digestKey]
			r["independent_input"] = c.Mode == "independent" && !t.Warmup && !t.Negative && (!exists || first == unit)
			if !t.Warmup && !t.Negative && !exists {
				seen[digestKey] = unit
			}
			if c.Mode != "independent" {
				r["input_seed_independence"] = "none: fixed/reproduction plaintexts; fresh encryption is not a new independent input"
			} else if len(c.Seeds) > 0 {
				r["input_seed_independence"] = "distinct operator root seeds; statistical independence of operator choices is unverified"
			} else {
				r["input_seed_independence"] = "distinct crypto/rand root seeds with domain-separated input generation; no claim of information-theoretic independence"
			}
			r["duplicate_plaintext_input"] = exists && first != unit
			r["input_group_id"] = t.InputGroup
		})
		tm.stage("key_generation", func() {
			k = ctx.KeyGen(cap)
			material := k.AvailableEvaluationKeys()
			provisioned = material
			r["evaluation_key_material_created"] = true
			r["available_rotation_keys"] = material.Rotations
			r["relinearization_key_available"] = material.Relin
			r["missing_rotation_keys"] = missingKeys(required, material.Rotations)
			r["missing_relinearization_key"] = (honestRelin || attackRelin) && !material.Relin
		})
		tm.stage("encryption", func() {
			l := bfvpack.MakeLayout(p.encoded.Rows(), p.encoded.Cols(), t.Size.N, t.Size.Dim)
			in = k.Encrypt(p.encoded, l)
			if t.Scenario == "addition_kernel" {
				other = k.Encrypt(p.other, l)
			}
		})
		if t.Negative {
			honest = in
			r["honest_baseline_kind"] = "existing negative test passes input as evaluated output; no honest matmul run"
		} else {
			tm.stage("honest_evaluation", func() {
				switch t.Scenario {
				case "selective_scaling", "matmul_kernel":
					honest = k.PublicRightMatmul(in, p.x.B, t.Size.Ell)
				case "addition_kernel":
					honest = k.Add(in, other)
				default:
					honest = k.Square(in)
				}
			})
			tm.stage("honest_decryption", func() {
				hc = k.Decrypt(honest)
				r["honest_decrypted_augmented_output"] = rows(hc)
				ok := hc.Equal(p.full)
				r["honest_correct"] = ok
				if !ok {
					panic("measurement integrity error: honest BFV output differs from plaintext reference; attack not executed")
				}
			})
		}
		meter = &bfvpack.OperationMeter{}
		k.Meter = meter
		k.ResetCount()
		// Attack rotations are composed from the provisioned keys (rotation composition).
		attacks.BeginSynthesis(provisioned.Rotations)
		tm.stage("evaluation", func() { changed = attackCall(k, in, honest, t) })
		tm.stage("decryption", func() {
			actual = k.Decrypt(changed)
			r["actual_augmented_output"] = rows(actual)
			r["actual_output"] = rows(actual.TopRows(t.Size.N))
		})
		tm.stage("analysis", func() {
			d, magnitude, count, e := delta(ctx.Field(), actual.TopRows(t.Size.N), p.correct)
			if e != nil {
				panic(e)
			}
			r["output_difference"] = Record{"definition": "entrywise (actual-expected) mod 65537, canonical residues", "values": d}
			r["error_magnitude"] = magnitude
			r["error_magnitude_definition"] = "max over entries of min(delta,65537-delta); centered modular L-infinity; not real-number approximation error"
			r["changed_entry_count"] = count
			r["wrong_output"] = count > 0
			if !t.Negative {
				r["checksum_rows_unchanged"] = checksumEqual(actual, hc, t.Size.N)
				if p.h != nil {
					target := 0
					if t.Scenario == "addition_kernel" {
						target = 1
					}
					matches := kernelMatches(ctx, actual, hc, p.h, target, t.Size.N)
					r["kernel_delta_matches"] = matches
					if !matches {
						panic("measurement integrity error: BFV kernel delta differs from mathematical reference")
					}
				}
				if t.Scenario == "square_permute" || t.Scenario == "square_rescale" {
					got, want := matrix.ColumnProducts(ctx.Field(), actual.TopRows(t.Size.N)), matrix.ColumnProducts(ctx.Field(), p.correct)
					r["actual_column_products"] = got
					r["expected_column_products"] = want
					r["column_products_preserved"] = equalVec(got, want)
				}
			}
		})
	})
	synthChains := attacks.EndSynthesis()
	sharedNS := attackNow().Sub(start).Nanoseconds()
	r["shared_pipeline_time_ns"] = sharedNS
	r["execution_status"] = status
	r["error_message"] = msg
	r["error_stack"] = stack
	diagnoseRotationFailure(r, tm.phase, status, msg, stack, meter)
	if status != "completed" {
		r["error_stage"] = tm.phase
		r["attack_success"] = Missing
		r["accepted"] = Missing
	}
	meterRecord(r, meter)
	// Provisioned versus used keys, and the composition chains.
	var usedRot []int
	usedRelin := false
	if meter != nil {
		usedRot = append([]int{}, meter.CompletedRotations...)
		usedRelin = meter.Completed.Relin > 0
	}
	r["key_provisioning_detail"] = KeyProvisioningDetail(t.Profile, provisioned, usedRot, usedRelin, synthChains)
	verify := func(name string) dataseal.VerifyResult {
		switch t.Scenario {
		case "selective_scaling", "matmul_kernel":
			mode := dataseal.Original
			if name == "dataseal_strengthened" {
				mode = dataseal.Corrected
			}
			if name == "dataseal_appendix" {
				mode = dataseal.Appendix
			}
			return dataseal.MatmulVerify(ctx.Field(), p.mc, actual, mode)
		case "addition_kernel":
			return dataseal.AddVerify(ctx.Field(), p.ac, actual)
		default:
			return dataseal.SquareVerify(ctx.Field(), p.sc, actual)
		}
	}
	verifiers := modes(t.Scenario)
	if t.Negative {
		verifiers = []string{"not_applicable_negative_control"}
		r["verifier_not_reached"] = true
		if status == "completed" {
			r["execution_status"] = "runtime_error"
			r["error_message"] = "negative control unexpectedly returned; original regression requires a panic"
			r["accepted"] = Missing
			r["attack_success"] = Missing
		}
	}
	return emitVerifierRecords(r, verifiers, sharedNS, attackNow, verify, emit)
}
func equalVec(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
