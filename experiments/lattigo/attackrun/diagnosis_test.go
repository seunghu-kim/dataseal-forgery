package attackrun

import (
	"dsfgo/bfvpack"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestObservedMissingRotationDiagnosis(t *testing.T) {
	for _, tc := range []struct {
		name     string
		offset   int
		explicit bool
	}{
		{"matmul_kernel", 15, true}, {"addition_kernel", -1, false},
		{"square_permute", -10, false}, {"missing_key_control", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := "runtime error: invalid memory address or nil pointer dereference"
			stack := "rlwe.(*RotationKeySet).GetRotationKey\nbfv.(*evaluator).RotateColumns"
			if tc.explicit {
				msg = fmt.Sprintf("evaluator has no rotation key for rotation by %d", tc.offset)
			}
			r := Record{"execution_status": "panic", "available_rotation_keys": []int{}, "error_message": msg, "error_stack": stack, "attack_success": Missing}
			m := &bfvpack.OperationMeter{Attempted: bfvpack.OperationTotals{Rotate: 1}, AttemptedRotations: []int{tc.offset}}
			diagnoseRotationFailure(r, "evaluation", "panic", msg, stack, m)
			if r["execution_status"] != "unsupported_configuration" || r["observed_execution_status"] != "panic" || r["diagnosed_cause"] != "unsupported_capability" || r["error_message"] != msg || r["error_stack"] != stack || r["attack_success"] != Missing {
				t.Fatal(r)
			}
			for _, variant := range []string{"unrelated_nil", "available_key", "completed_rotation", "wrong_stage", "unmeasured_material"} {
				x := Record{"execution_status": "panic", "available_rotation_keys": []int{}}
				mm := *m
				trace := stack
				phase := "evaluation"
				switch variant {
				case "unrelated_nil":
					trace = "collector.nilBug"
				case "available_key":
					x["available_rotation_keys"] = []int{tc.offset}
				case "completed_rotation":
					mm.Completed.Rotate = 1
				case "wrong_stage":
					phase = "decryption"
				case "unmeasured_material":
					delete(x, "available_rotation_keys")
				}
				// Unrelated nil must use a nil message, not Lattigo's explicit missing-key error.
				message := msg
				if variant == "unrelated_nil" {
					message = "runtime error: invalid memory address or nil pointer dereference"
				}
				diagnoseRotationFailure(x, phase, "panic", message, trace, &mm)
				if x["execution_status"] != "panic" {
					t.Fatalf("masked %s: %v", variant, x)
				}
			}
		})
	}
}

func TestNonexecutedProvenanceValidator(t *testing.T) {
	r := syntheticRecord(t)
	r["trial_id"] = "synthetic-unsupported"
	r["execution_status"] = "unsupported_configuration"
	r["error_message"] = "synthetic implementation absent"
	r["verifier"] = "dataseal_square"
	r["wrong_output"], r["accepted"], r["attack_success"] = Missing, Missing, Missing
	unsupportedInputMetadata(r)
	n := syntheticRecord(t)
	n["trial_id"] = "synthetic-negative-control"
	n["execution_status"] = "unsupported_configuration"
	n["error_message"] = "synthetic missing key"
	n["verifier"] = "not_applicable_negative_control"
	n["seed"] = "fixed literal fixture"
	n["wrong_output"], n["accepted"], n["attack_success"] = Missing, Missing, Missing
	p := filepath.Join(t.TempDir(), "synthetic.json")
	if e := writeNew(p, []Record{r, n}); e != nil {
		t.Fatal(e)
	}
	b, e := exec.Command(validatorExe(t), "validate", "--input", p).CombinedOutput()
	if e != nil {
		t.Fatalf("%v: %s", e, b)
	}
	var result struct {
		Valid  bool                               `json:"valid"`
		Issues []struct{ Severity, Field string } `json:"issues"`
	}
	if e = json.Unmarshal(b, &result); e != nil {
		t.Fatal(e)
	}
	if !result.Valid {
		t.Fatal(string(b))
	}
	for _, issue := range result.Issues {
		if issue.Severity == "warning" && (issue.Field == "seed" || issue.Field == "verifier" || issue.Field == "mathematical_precondition" || issue.Field == "precondition_satisfied") {
			t.Fatal(string(b))
		}
	}
}
