package attackrun

import (
	"dsfgo/bfvpack"
	"dsfgo/dataseal"
	"dsfgo/field"
	"dsfgo/matrix"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func validatorExe(t *testing.T) string {
	t.Helper()
	_, exe := ValidatorPaths(repoRoot(t))
	if _, e := os.Stat(exe); e != nil {
		t.Skipf("validator not built (see scripts/build_and_test.sh): %v", e)
	}
	return exe
}
func testSchema(t *testing.T) schema {
	t.Helper()
	schemaPath, _ := ValidatorPaths(repoRoot(t))
	s, e := loadSchema(schemaPath)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func syntheticRecord(t *testing.T) Record {
	t.Helper()
	r := baseRecord(testSchema(t), Config{RunID: "unit-run", Mode: "fixed"}, task{Scenario: "selective_scaling", Profile: "honest_minimal", ID: "synthetic-ciphertext", Size: Size{3, 2, 2, 5}}, "synthetic-machine", "synthetic-metadata")
	r["data_origin"] = "synthetic_example"
	r["execution_status"] = "completed"
	r["error_message"] = Missing
	r["wrong_output"] = true
	r["mathematical_precondition"] = "none"
	r["independent_input"] = false
	return r
}
func ticking() func() time.Time {
	i := int64(0)
	return func() time.Time { i += 10; return time.Unix(0, i) }
}
func TestTimingBoundariesAndInterruptedStage(t *testing.T) {
	r := Record{}
	tm := timer{r: r, now: ticking()}
	tm.stage("evaluation", func() {})
	if r["evaluation_time_ns"] != int64(10) {
		t.Fatal(r)
	}
	status, msg, _ := guard(func() { tm.stage("decryption", func() { panic("synthetic original error") }) })
	if status != "panic" || msg != "synthetic original error" || r["decryption_time_ns"] != int64(10) || r["incomplete_timing_stage"] != "decryption" {
		t.Fatal(status, msg, r)
	}
	b := timingBoundary()
	if !strings.Contains(b["evaluation"].(string), "excludes honest evaluation") || !strings.Contains(b["total"].(string), "two disjoint observed intervals") {
		t.Fatal("boundary lost")
	}
}
func TestPairedVerifierSerializationAndExistingSchema(t *testing.T) {
	r := syntheticRecord(t)
	meterRecord(r, &bfvpack.OperationMeter{Attempted: bfvpack.OperationTotals{MulPt: 1}, Completed: bfvpack.OperationTotals{MulPt: 1}})
	r["expected_output"] = [][]uint64{{1}}
	r["actual_output"] = [][]uint64{{2}}
	r["output_difference"] = Record{"definition": "synthetic modular delta", "values": [][]uint64{{1}}}
	r["error_magnitude"] = 1
	var out []Record
	e := emitVerifierRecords(r, []string{"dataseal_original", "dataseal_strengthened"}, 100, ticking(), func(name string) dataseal.VerifyResult {
		return dataseal.VerifyResult{ShapeOK: true, Checks: map[string]bool{"synthetic_check": name == "dataseal_original"}}
	}, func(x Record) error { out = append(out, x); return nil })
	if e != nil {
		t.Fatal(e)
	}
	if out[0]["attack_success"] != true || out[1]["attack_success"] != false || r["accepted"] != Missing || out[0]["paired_ciphertext_id"] != out[1]["paired_ciphertext_id"] || out[0]["trial_id"] == out[1]["trial_id"] {
		t.Fatal("paired observations conflated")
	}
	for _, row := range out {
		if row["total_time_ns"] != int64(110) {
			t.Fatal("other verifier time included")
		}
	}
	// Use the offline validator itself, not a second validation implementation.
	d := t.TempDir()
	file := filepath.Join(d, "synthetic.json")
	if e = writeNew(file, out); e != nil {
		t.Fatal(e)
	}
	tool := validatorExe(t)
	cmd := exec.Command(tool, "validate", "--input", file)
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("existing schema validator rejected synthetic observations: %v\n%s", e, b)
	}
	var roundtrip []Record
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &roundtrip); e != nil {
		t.Fatal(e)
	}
	if roundtrip[0]["data_origin"] != "synthetic_example" {
		t.Fatal("unit fixture misrepresented as experimental evidence")
	}
}
func TestVerifierPanicPreservedAndNotFailure(t *testing.T) {
	r := syntheticRecord(t)
	var out Record
	e := emitVerifierRecords(r, []string{"dataseal_original"}, 100, ticking(), func(string) dataseal.VerifyResult { panic("original synthetic verifier exception") }, func(x Record) error { out = x; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if out["execution_status"] != "panic" || out["error_message"] != "original synthetic verifier exception" || out["accepted"] != Missing || out["attack_success"] != Missing {
		t.Fatal(out)
	}
}
func TestPreVerifierErrorDoesNotInvokeVerifier(t *testing.T) {
	r := syntheticRecord(t)
	r["execution_status"] = "panic"
	r["error_message"] = "synthetic missing-key panic"
	r["wrong_output"] = Missing
	called := false
	var out Record
	e := emitVerifierRecords(r, []string{Missing}, 80, ticking(), func(string) dataseal.VerifyResult { called = true; return dataseal.VerifyResult{} }, func(x Record) error { out = x; return nil })
	if e != nil || called || out["attack_success"] != Missing || out["accepted"] != Missing {
		t.Fatal("error became verifier rejection")
	}
}
func TestModularDifferenceMagnitude(t *testing.T) {
	f := field.New(65537)
	want := matrix.FromInts(f, [][]int64{{0, 0, 1}})
	got := matrix.FromInts(f, [][]int64{{65536, 32769, 1}})
	d, max, count, e := delta(f, got, want)
	if e != nil || d[0][0] != 65536 || max != 32768 || count != 2 {
		t.Fatal(d, max, count, e)
	}
}
func TestInputModesAndSeedProvenance(t *testing.T) {
	f := field.New(65537)
	s := Size{3, 5, 2, 8}
	a, e := makeInputs(f, "independent", "matmul_kernel", s, 100)
	if e != nil {
		t.Fatal(e)
	}
	same, _ := makeInputs(f, "independent", "matmul_kernel", s, 100)
	other, _ := makeInputs(f, "independent", "matmul_kernel", s, 101)
	if a.Digest != same.Digest || a.Digest == other.Digest {
		t.Fatal("input seed identity incorrect")
	}
	fixed, _ := makeInputs(f, "fixed", "matmul_kernel", Size{3, 2, 2, 5}, 1)
	repeat, _ := makeInputs(f, "fixed", "matmul_kernel", Size{3, 2, 2, 5}, 999)
	if fixed.Digest != repeat.Digest {
		t.Fatal("fixed fixture changed")
	}
	k, nonzero, dot := referenceKernel(f, fixed, 3)
	if !nonzero || dot != 0 || k[0] != 8 || k[2] != 65529 {
		t.Fatal("reference precondition instrumentation incorrect")
	}
}
func TestCapabilitiesAndNoParameterSubstitution(t *testing.T) {
	s := Size{3, 2, 2, 5}
	for _, scenario := range scenarios {
		minTask := task{Scenario: scenario, Profile: "honest_minimal", Size: s}
		extTask := minTask
		extTask.Profile = "extended"
		min, _, _, _, _ := requirements(minTask)
		ext, _, _, _, _ := requirements(extTask)
		if scenario == "addition_kernel" && (len(min.Rotations) != 0 || min.Relin || !ext.Relin) {
			t.Fatal("addition minimum changed")
		}
		if scenario == "square_rescale" && (!min.Relin || len(min.Rotations) > 0 || !ext.Relin || len(ext.Rotations) > 0) {
			t.Fatal("rescaling extended loop must retain the existing identical capability set")
		}
		if scenario == "matmul_kernel" && (min.Relin || !ext.Relin || len(ext.Rotations) <= len(min.Rotations)) {
			t.Fatal("kernel profiles conflated")
		}
	}
}
func TestConfigurationRejectsDuplicatesAndUnsafeShapes(t *testing.T) {
	c := Config{RunID: "run", Output: "new", Metadata: "meta", Schema: "schema", Validator: "validator", Mode: "independent", Trials: 2, Seeds: []uint64{1, 1}}
	if c.Validate() == nil {
		t.Fatal("duplicate independent seeds accepted")
	}
	c.Seeds = []uint64{1, 2}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Sizes = []Size{{3, 2, 2, 91}}
	if c.Validate() == nil {
		t.Fatal("PN14 packing overflow accepted")
	}
}
func TestWriteNewDoesNotOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trial.json")
	if e := writeNew(p, Record{"unit": "synthetic"}); e != nil {
		t.Fatal(e)
	}
	if writeNew(p, Record{"replacement": true}) == nil {
		t.Fatal("completed result overwritten")
	}
}

func TestAllScenarioRecordsUseExistingValidatorWithoutAttacks(t *testing.T) {
	s := testSchema(t)
	c := Config{RunID: "synthetic-all-scenarios", Mode: "fixed"}
	records := []Record{}
	for _, scenario := range scenarios {
		for _, profile := range []string{"honest_minimal", "extended"} {
			task := task{Scenario: scenario, Profile: profile, ID: "synthetic-" + scenario + "-" + profile, Size: Size{3, 2, 2, 5}}
			r := baseRecord(s, c, task, "synthetic-machine", "synthetic-metadata")
			r["data_origin"] = "synthetic_example"
			r["seed"] = "unit fixture, no input execution"
			r["mathematical_precondition"] = "synthetic test condition"
			r["precondition_satisfied"] = true
			r["wrong_output"] = true
			r["execution_status"] = "completed"
			r["error_message"] = Missing
			r["independent_input"] = false
			if e := emitVerifierRecords(r, modes(scenario), 50, ticking(), func(string) dataseal.VerifyResult { return dataseal.VerifyResult{ShapeOK: true} }, func(x Record) error { records = append(records, x); return nil }); e != nil {
				t.Fatal(e)
			}
		}
	}
	r := baseRecord(s, c, task{ID: "unsupported-unit", Scenario: "square_rescale", Profile: "not_applicable", Size: Size{3, 2, 2, 5}}, "synthetic-machine", "synthetic-metadata")
	r["data_origin"] = "synthetic_example"
	r["workload"] = "square_zero_product"
	r["verifier"] = "dataseal_square"
	r["execution_status"] = "unsupported_configuration"
	r["error_message"] = "synthetic unsupported implementation record; no BFV execution"
	records = append(records, r)
	n := baseRecord(s, c, task{ID: "missing-key-unit", Scenario: "matmul_kernel", Profile: "negative_control", Size: Size{3, 2, 2, 5}, Negative: true}, "synthetic-machine", "synthetic-metadata")
	n["data_origin"] = "synthetic_example"
	n["verifier"] = Missing
	n["execution_status"] = "panic"
	n["error_message"] = "synthetic missing-key exception; no attack executed"
	records = append(records, n)
	d := t.TempDir()
	p := filepath.Join(d, "synthetic-all.json")
	if e := writeNew(p, records); e != nil {
		t.Fatal(e)
	}
	tool := validatorExe(t)
	b, e := exec.Command(tool, "validate", "--input", p).CombinedOutput()
	if e != nil {
		t.Fatalf("scenario schema compatibility: %v\n%s", e, b)
	}
}
func TestMetadataPlanCannotReuseWrongCountsOrProfile(t *testing.T) {
	c := Config{Trials: 20, Warmups: 1}
	m := Record{"repetition_count_operator_supplied": float64(20), "warmup_count_operator_supplied": float64(1), "bfv_parameter_profiles_operator_supplied": []interface{}{"PN14QP438"}}
	if e := checkPlanMetadata(c, m); e != nil {
		t.Fatal(e)
	}
	m["repetition_count_operator_supplied"] = float64(1)
	if checkPlanMetadata(c, m) == nil {
		t.Fatal("stale repetition metadata accepted")
	}
	m["repetition_count_operator_supplied"] = float64(20)
	m["bfv_parameter_profiles_operator_supplied"] = []interface{}{"PN13QP218"}
	if checkPlanMetadata(c, m) == nil {
		t.Fatal("wrong HE profile metadata accepted")
	}
}
