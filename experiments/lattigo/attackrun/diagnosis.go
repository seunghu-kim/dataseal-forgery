package attackrun

import (
	"dsfgo/bfvpack"
	"fmt"
	"strings"
)

// A panic is diagnosed as a missing rotation key only when the unfinished
// rotation and the missing key are both observed.
func diagnoseRotationFailure(r Record, phase, status string, message, stack interface{}, m *bfvpack.OperationMeter) {
	r["observed_execution_status"] = status
	if status != "panic" || phase != "evaluation" || m == nil || m.Attempted.Rotate != m.Completed.Rotate+1 || len(m.AttemptedRotations) == 0 {
		return
	}
	offset := m.AttemptedRotations[len(m.AttemptedRotations)-1]
	available, ok := r["available_rotation_keys"].([]int)
	if !ok || len(missingKeys([]int{offset}, available)) == 0 {
		return
	}
	msg, trace := fmt.Sprint(message), fmt.Sprint(stack)
	explicit := msg == fmt.Sprintf("evaluator has no rotation key for rotation by %d", offset)
	nilLookup := strings.Contains(msg, "nil pointer dereference") && strings.Contains(trace, "rlwe.(*RotationKeySet).GetRotationKey") && strings.Contains(trace, "bfv.(*evaluator).RotateColumns")
	if !explicit && !nilLookup {
		return
	}
	// The diagnosis is added beside the original observation; error_message and
	// error_stack stay untouched.
	r["execution_status"] = "unsupported_configuration"
	r["diagnosed_cause"] = "unsupported_capability"
	r["failed_rotation_offset"] = offset
	r["unsupported_capability_reason"] = fmt.Sprintf("observed rotation %d cannot execute: actual evaluation-key material has no corresponding rotation key", offset)
}

func unsupportedInputMetadata(r Record) {
	r["seed"] = "not_applicable: no BFV implementation; no input generated"
	r["seed_provenance"] = r["seed"]
	// This is a configuration-availability record, not a mathematical trial.
	r["mathematical_precondition"] = "none"
	r["precondition_satisfied"] = Missing
	r["precondition_evaluation_status"] = "not_applicable: implementation absent; no mathematical trial executed"
	r["unsupported_scenario_precondition"] = "zero column product; not evaluated"
}
