package attackrun

import (
	"dsfgo/attacks"
	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"fmt"
	"runtime/debug"
	"sort"
	"time"
)

type task struct {
	Scenario, Profile, ID, InputGroup string
	Size                              Size
	Seed                              uint64
	Warmup, Negative                  bool
}

func modes(scenario string) []string {
	switch scenario {
	case "selective_scaling", "matmul_kernel":
		return []string{"dataseal_original", "dataseal_strengthened", "dataseal_appendix"}
	case "addition_kernel":
		return []string{"dataseal_add"}
	default:
		return []string{"dataseal_square"}
	}
}
func unique(v []int) []int {
	set := map[int]bool{}
	for _, x := range v {
		if x != 0 {
			set[x] = true
		}
	}
	out := []int{}
	for x := range set {
		out = append(out, x)
	}
	sort.Ints(out)
	return out
}
func kernelRotations(n, dim, target int) []int {
	v := []int{-target, 1 - target, n * dim}
	for i := 1; i < n; i++ {
		v = append(v, -i*dim)
	}
	return unique(v)
}
func requirements(t task) (bfvpack.Capability, []int, []int, bool, bool) {
	honest, attack := []int{}, []int{}
	honestRelin, attackRelin := false, false
	switch t.Scenario {
	case "selective_scaling", "matmul_kernel":
		honest = bfvpack.PublicMatmulRotations(t.Size.D, t.Size.Ell)
	case "square_permute", "square_rescale":
		honestRelin = true
	}
	switch t.Scenario {
	case "matmul_kernel":
		attack = kernelRotations(t.Size.N, t.Size.Dim, 0)
		attackRelin = true
	case "addition_kernel":
		attack = kernelRotations(t.Size.N, t.Size.Dim, 1)
		attackRelin = true
	case "square_permute":
		attack = unique([]int{2 * t.Size.Dim, -2 * t.Size.Dim})
	}
	cap := bfvpack.Capability{Relin: honestRelin, Rotations: unique(honest)}
	if t.Profile == "extended" {
		cap.Rotations = unique(append(append([]int{}, honest...), attack...))
		cap.Relin = honestRelin || attackRelin || t.Scenario == "selective_scaling"
	}
	// Key profiles take their key set from provision.go, independent of scenario.
	switch t.Profile {
	case "composite":
		cap = CompositeCapability(t.Size.D, t.Size.Ell)
	case "matmul_only":
		cap = MatmulOnlyCapability(t.Size.D, t.Size.Ell)
	case "squaring_only":
		cap = SquaringOnlyCapability()
	case "addition_only":
		cap = AdditionOnlyCapability()
	case "direct_index":
		cap = DirectIndexCapability(t.Size.D, t.Size.Ell, attack)
	}
	if t.Negative {
		honest = []int{}
		honestRelin = false
		cap = bfvpack.Capability{Rotations: []int{}}
	}
	return cap, honest, attack, honestRelin, attackRelin
}
func missingKeys(required, available []int) []int {
	set := map[int]bool{}
	for _, x := range available {
		set[x] = true
	}
	v := []int{}
	for _, x := range required {
		if !set[x] {
			v = append(v, x)
		}
	}
	return unique(v)
}
func timingBoundary() Record {
	return Record{
		"definition":      "Experiment A: preparation, keygen, input encryption, honest baseline evaluation/decryption, existing attack evaluation, returned-output decryption, diagnostic analysis and this verifier; excludes context startup, metadata, serialization and other verifiers",
		"included_stages": []string{"preparation", "key_generation", "encryption", "honest_evaluation", "honest_decryption", "evaluation", "decryption", "analysis", "verification"},
		"evaluation":      "existing attack function only; includes its plaintext mask construction/encoding and its internal relinearization; excludes honest evaluation and returned decryption",
		"preparation":     "input generation, original DataSeal encoding, plaintext references, mathematical preconditions",
		"total":           "sum of two disjoint observed intervals: shared pipeline wall interval plus this verifier interval; not a monolithic wall time and not a sum of stage medians",
		"verification":    "original DataSeal verifier and Accepted only; multiple verifier records share one paired ciphertext",
		"errors":          "stage durations are elapsed-until-error when interrupted; failed timing stage identified separately",
		"unit":            "ns", "batch": 1,
	}
}
func baseRecord(s schema, c Config, t task, machine, metadata string) Record {
	r := Record{}
	for _, k := range s.Required {
		r[k] = Missing
	}
	ell := t.Size.Ell
	if t.Scenario == "addition_kernel" || t.Scenario == "square_permute" || t.Scenario == "square_rescale" {
		ell = t.Size.D
	}
	work := t.Scenario
	if t.Negative {
		work = "missing_key_control"
	}
	for k, v := range (Record{"schema_version": SchemaVersion, "experiment_id": "Experiment-A", "run_id": c.RunID, "trial_id": t.ID, "experiment_category": "attack", "workload": work, "implementation": "lattigo_v2_bfv", "input_dimensions": Record{"n": t.Size.N, "d": t.Size.D, "ell": ell, "padded_dim": t.Size.Dim}, "parameter_profile": "PN14QP438", "evaluation_key_profile": t.Profile, "data_origin": "fresh_measurement", "machine_id": machine, "metadata_id": metadata, "time_unit": "ns", "is_warmup": t.Warmup, "timing_boundary": timingBoundary(), "execution_status": "not_started", "error_message": "pipeline not started", "sample_mode": c.Mode, "input_seed_independence": "not_established", "paired_ciphertext_id": t.ID, "workload_definition": Record{"expression": workloadExpression(t.Scenario), "sample_mode": c.Mode, "negative_control": t.Negative, "packing": "existing row-major single ciphertext; padded_dim recorded in input_dimensions", "public_constants": Record{"scaling_factor": 3, "gamma": 3, "alpha": 7, "kernel_columns": []int{0, 1}}}}) {
		r[k] = v
	}
	r["measurement_clock"] = attackClockInfo()
	r["timing_boundary_version"] = "A-attack-QPC-v1"
	// evaluation_key_profile carries the validator's category; the profile name is
	// kept separately.
	r["internal_evaluation_key_profile"] = t.Profile
	if enum, ok := ValidatorKeyProfile(t.Profile); ok {
		r["evaluation_key_profile"] = enum
	}
	return r
}
func workloadExpression(s string) string {
	switch s {
	case "selective_scaling", "matmul_kernel":
		return "A[n,d]*B[d,ell] mod 65537, A encrypted and B public"
	case "addition_kernel":
		return "A[n,d]+B[n,d] mod 65537, both encrypted"
	default:
		return "A[n,d] pointwise squared mod 65537, corrected Algorithm 6 verifier"
	}
}

type timer struct {
	r     Record
	now   func() time.Time
	phase string
}

func (t *timer) stage(name string, fn func()) {
	t.phase = name
	if qpcEnabled() {
		measureQPCStage(t.r, name, fn)
		return
	}
	start := t.now()
	finished := false
	defer func() {
		t.r[name+"_time_ns"] = t.now().Sub(start).Nanoseconds()
		if !finished {
			t.r["incomplete_timing_stage"] = name
		}
	}()
	fn()
	finished = true
}
func guard(fn func()) (status string, message, stack interface{}) {
	status = "completed"
	message, stack = Missing, Missing
	defer func() {
		if p := recover(); p != nil {
			status = "panic"
			message = fmt.Sprint(p)
			stack = string(debug.Stack())
		}
	}()
	fn()
	return
}
func delta(f field.Field, actual, expected matrix.Mat) ([][]uint64, uint64, int, error) {
	if actual.Rows() != expected.Rows() || actual.Cols() != expected.Cols() {
		return nil, 0, 0, fmt.Errorf("returned data shape differs from expected")
	}
	d := make([][]uint64, actual.Rows())
	max := uint64(0)
	changed := 0
	for i := range d {
		d[i] = make([]uint64, actual.Cols())
		for j := range d[i] {
			v := f.Sub(actual.At(i, j), expected.At(i, j))
			d[i][j] = v
			if v != 0 {
				changed++
			}
			a := v
			if f.P()-v < a {
				a = f.P() - v
			}
			if a > max {
				max = a
			}
		}
	}
	return d, max, changed, nil
}
func meterRecord(r Record, m *bfvpack.OperationMeter) {
	if m == nil {
		return
	}
	c := m.Completed
	r["rotation_count"] = c.Rotate
	r["ciphertext_multiplication_count"] = c.MulCt
	r["plaintext_multiplication_count"] = c.MulPt
	r["addition_count"] = c.Add
	r["subtraction_count"] = c.Sub
	r["relinearization_count"] = c.Relin
	r["key_switch_count"] = Missing
	r["operation_count_source"] = "measured"
	r["operation_count_scope"] = "completed evaluator calls at instrumented wrappers; separate attempted totals; ct multiplication completion does not imply relin completion"
	r["attempted_operation_counts"] = m.Attempted
	r["completed_operation_counts"] = m.Completed
	r["attempted_rotation_offsets"] = append([]int{}, m.AttemptedRotations...)
	r["completed_rotation_offsets"] = append([]int{}, m.CompletedRotations...)
}

// The verifier is a callback so this can be tested without encryption.
func emitVerifierRecords(common Record, verifiers []string, sharedNS int64, now func() time.Time, verify func(string) dataseal.VerifyResult, emit func(Record) error) error {
	for _, name := range verifiers {
		r := Record{}
		for k, v := range common {
			r[k] = v
		}
		r["verifier"] = name
		r["trial_id"] = fmt.Sprint(common["trial_id"]) + "-" + name
		if common["execution_status"] == "completed" {
			tm := timer{r: r, now: now}
			status, msg, stack := guard(func() {
				tm.stage("verification", func() {
					v := verify(name)
					r["verifier_checks"] = v.Checks
					r["shape_ok"] = v.ShapeOK
					r["accepted"] = v.Accepted()
					wrong, ok := r["wrong_output"].(bool)
					if !ok {
						panic("missing correctness observation before verification")
					}
					r["attack_success"] = wrong && v.Accepted()
				})
			})
			r["execution_status"] = status
			r["error_message"] = msg
			r["error_stack"] = stack
			if status != "completed" {
				r["accepted"] = Missing
				r["attack_success"] = Missing
				r["error_stage"] = "verification"
			}
			r["total_time_ns"] = sharedNS + r["verification_time_ns"].(int64)
		} else {
			r["total_time_ns"] = sharedNS
		}
		if e := emit(r); e != nil {
			return e
		}
	}
	return nil
}

// referenceKernel checks h != 0 and k^T h = 0 on client plaintext: an eligibility
// check, not part of the attack.
func referenceKernel(f field.Field, x inputs, n int) ([]uint64, bool, uint64) {
	w := matrix.MatTVec(f, x.A, x.K)
	h := make([]uint64, n)
	nz := false
	for i := range h {
		h[i] = f.Sub(f.Mul(w[1], x.A.At(i, 0)), f.Mul(w[0], x.A.At(i, 1)))
		nz = nz || h[i] != 0
	}
	return h, nz, f.Dot(x.K, h)
}
func attackCall(k bfvpack.Keys, in, honest bfvpack.Cipher, t task) bfvpack.Cipher {
	switch t.Scenario {
	case "selective_scaling":
		return attacks.SelectiveScaling(k, field.New(65537), honest, t.Size.N, 3)
	case "matmul_kernel":
		return attacks.KernelAdjustedOutput(k, in, honest, t.Size.N, attacks.KernelChoice{ColA: 0, ColB: 1, Target: 0})
	case "addition_kernel":
		return attacks.KernelAdjustedOutput(k, in, honest, t.Size.N, attacks.KernelChoice{ColA: 0, ColB: 1, Target: 1})
	case "square_permute":
		return attacks.SquarePermute(k, honest, t.Size.N, 0, 2, 1)
	default:
		return attacks.SquareRescale(k, field.New(65537), honest, 1, 0, 2, 3)
	}
}
