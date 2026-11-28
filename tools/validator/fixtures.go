package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Deliberately invented values: never run any workload or import HE packages.
func exampleRecord(id string) Record {
	r := Record{}
	for _, k := range fields() {
		r[k] = missing
	}
	for _, k := range optionalFields {
		r[k] = missing
	}
	defaults := Record{"schema_version": version, "experiment_id": "SYNTHETIC-attack-example", "run_id": "SYNTHETIC-run-001", "trial_id": id, "experiment_category": "attack", "workload": "synthetic-vector-transform", "workload_definition": "Synthetic scalar output comparison; no DataSeal or BFV operation executed", "implementation": "synthetic_method_A", "verifier": "synthetic_verifier", "input_dimensions": map[string]any{"n": 8, "d": 1, "ell": 1}, "seed": "SYNTHETIC-fixed-literal", "parameter_profile": "PN14QP438", "evaluation_key_profile": "honest_minimal", "expected_output": []any{1}, "actual_output": []any{2}, "output_difference": []any{1}, "error_magnitude": 1, "wrong_output": true, "accepted": true, "attack_success": true, "mathematical_precondition": "synthetic nonzero difference", "precondition_satisfied": true, "available_rotation_keys": []any{}, "required_rotation_keys": []any{}, "relinearization_key_available": false, "rotation_count": 0, "ciphertext_multiplication_count": 0, "plaintext_multiplication_count": 1, "addition_count": 0, "key_switch_count": missing, "operation_count_source": "analytical", "operation_count_scope": "synthetic_example_only", "preparation_time_ns": 100, "encryption_time_ns": 200, "evaluation_time_ns": 300, "verification_time_ns": 100, "decryption_time_ns": 100, "total_time_ns": 800, "time_unit": "ns", "timing_boundary": map[string]any{"definition": "Synthetic end-to-end cost; preparation, encrypt, evaluate, decrypt, verify included; correctness reference and keygen excluded", "included_stages": []any{"preparation", "encryption", "evaluation", "decryption", "verification"}, "packing_relation": "subset of preparation; stage medians are non-additive"}, "data_origin": "synthetic_example", "machine_id": "SYNTHETIC-NOT-A-REAL-COMPUTER", "metadata_id": "SYNTHETIC-metadata", "is_warmup": false, "execution_status": "completed", "error_message": missing, "he_security_target_bits": 128}
	for k, v := range defaults {
		r[k] = v
	}
	return r
}
func clone(r Record) Record {
	b := []byte(canonical(r))
	var c Record
	if e := decode(b, &c); e != nil {
		panic(e)
	}
	return c
}
func fixtureRows() []Record {
	rows := []Record{}
	for i := 0; i < 6; i++ {
		r := exampleRecord(fmt.Sprintf("attack-%02d", i))
		if i >= 3 {
			r["evaluation_key_profile"] = "extended"
		}
		switch i {
		case 1:
			r["accepted"] = false
			r["attack_success"] = false
		case 2:
			r["precondition_satisfied"] = false
		case 4:
			r["execution_status"] = "panic"
			r["error_message"] = "SYNTHETIC missing-key panic, not an executed operation"
			r["accepted"] = missing
			r["wrong_output"] = missing
			r["attack_success"] = missing
			r["actual_output"] = missing
			r["output_difference"] = missing
			r["error_magnitude"] = missing
			r["evaluation_time_ns"] = missing
		case 5:
			r["accepted"] = missing
			r["attack_success"] = missing
		}
		rows = append(rows, r)
	}
	for _, n := range []int{8, 128} {
		for _, method := range []string{"synthetic_method_A", "private_sketch_synthetic"} {
			for i := 0; i < 4; i++ {
				r := exampleRecord(fmt.Sprintf("perf-%d-%s-%d", n, method, i))
				r["experiment_id"] = "SYNTHETIC-performance-example"
				r["experiment_category"] = "performance"
				r["workload"] = "synthetic-public-right-matmul"
				r["workload_definition"] = "Synthetic square public-right multiplication A[n,n] B[n,n] modulo 65537, keygen excluded"
				r["implementation"] = method
				r["input_dimensions"] = map[string]any{"n": n, "d": n, "ell": n}
				r["wrong_output"] = false
				r["actual_output"] = []any{1}
				r["output_difference"] = []any{0}
				r["error_magnitude"] = 0
				r["attack_success"] = false
				r["mathematical_precondition"] = "none"
				r["precondition_satisfied"] = missing
				r["total_time_ns"] = int64(1000000 * (i + 1) * n)
				r["evaluation_time_ns"] = int64(100000 * (i + 1) * n)
				r["preparation_time_ns"] = int64(10000 * (i + 1) * n)
				r["encryption_time_ns"] = int64(20000 * (i + 1) * n)
				r["packing_time_ns"] = int64(1000 * (i + 1) * n)
				r["direct_computation_time_ns"] = int64(50000 * (i + 1) * n)
				if method == "private_sketch_synthetic" {
					r["sketch_p"] = 65537
					r["sketch_r"] = 10
					r["sketch_Q_auth"] = uint64(4294967296)
				}
				rows = append(rows, r)
			}
		}
	}
	// Verify that results with different parameter profiles are grouped separately.
	p13 := clone(rows[6])
	p13["trial_id"] = "perf-PN13-separate"
	p13["parameter_profile"] = "PN13QP218"
	rows = append(rows, p13)
	for _, q := range []int{1, 2, 4, 8} {
		for _, policy := range []string{"fresh", "reuse"} {
			for i := 0; i < 3; i++ {
				r := clone(rows[6])
				r["experiment_id"] = "SYNTHETIC-reuse-example"
				r["trial_id"] = fmt.Sprintf("reuse-%d-%s-%d", q, policy, i)
				r["input_reuse_programs"] = q
				r["reuse_policy"] = policy
				r["program_family_id"] = "SYNTHETIC-distinct-approved-public-programs"
				r["total_time_ns"] = int64((q*10 + i + 1) * 1000000)
				rows = append(rows, r)
			}
		}
	}
	return rows
}
func writeExamples(out string) error {
	if e := os.Mkdir(out, 0755); e != nil {
		return e
	}
	rows := fixtureRows()
	if e := WriteJSON(filepath.Join(out, "synthetic-trials.json"), rows); e != nil {
		return e
	}
	if e := WriteCSV(filepath.Join(out, "synthetic-trials.csv"), rows); e != nil {
		return e
	}
	duplicate := []Record{clone(rows[0]), clone(rows[0])}
	badMissing := clone(rows[0])
	delete(badMissing, "accepted")
	badSuccess := clone(rows[0])
	badSuccess["attack_success"] = false
	badUnits := clone(rows[0])
	badUnits["time_unit"] = "ms"
	badError := clone(rows[0])
	badError["execution_status"] = "runtime_error"
	badError["error_message"] = "SYNTHETIC runtime exception"
	badError["attack_success"] = false
	for name, records := range map[string][]Record{"invalid-duplicate.json": duplicate, "invalid-missing-field.json": {badMissing}, "invalid-success.json": {badSuccess}, "invalid-units.json": {badUnits}, "invalid-error-classification.json": {badError}} {
		if e := WriteJSON(filepath.Join(out, name), records); e != nil {
			return e
		}
	}
	return exclusive(filepath.Join(out, "SYNTHETIC-ONLY.txt"), []byte("ALL RECORDS ARE INVENTED FIXTURES. No cryptographic operation or benchmark was executed. Never use these records as experimental evidence.\n"))
}
