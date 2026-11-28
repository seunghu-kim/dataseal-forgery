package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaParsingAndCSVRoundTrip(t *testing.T) {
	rows := fixtureRows()
	if v := Validate(rows); !v.Valid {
		t.Fatalf("fixtures invalid: %+v", v.Issues)
	}
	d := t.TempDir()
	p := filepath.Join(d, "data.csv")
	if e := WriteCSV(p, rows); e != nil {
		t.Fatal(e)
	}
	got, e := ReadRecords(p)
	if e != nil {
		t.Fatal(e)
	}
	if canonical(rows) != canonical(got) {
		t.Fatal("CSV round trip changes observations")
	}
	p = filepath.Join(d, "data.json")
	if e = WriteJSON(p, rows); e != nil {
		t.Fatal(e)
	}
	got, e = ReadRecords(p)
	if e != nil || len(got) != len(rows) {
		t.Fatal(e)
	}
	if canonical(JSONSchema()["required"]) != canonical(fields()) {
		t.Fatal("schema fields drift")
	}
}
func TestUnavailableObservationsStayMissing(t *testing.T) {
	r := exampleRecord("missing")
	r["accepted"] = missing
	r["attack_success"] = missing
	r["evaluation_time_ns"] = missing
	if !Validate([]Record{r}).Valid {
		t.Fatal("explicit unavailable value rejected")
	}
	s := Analyze([]Record{r})[0]
	if s.Decisive != 0 || s.Conditional.Value != missing || s.Metrics["evaluation_time_ns"].N != 0 {
		t.Fatal("missing observations inferred")
	}
	r["attack_success"] = false
	if Validate([]Record{r}).Valid {
		t.Fatal("missing acceptance silently interpreted as false")
	}
}
func TestDuplicateDetectionAcrossProfiles(t *testing.T) {
	r := exampleRecord("same")
	r2 := clone(r)
	r2["parameter_profile"] = "PN13QP218"
	r2["evaluation_key_profile"] = "extended"
	if Validate([]Record{r, r2}).Valid {
		t.Fatal("duplicate ID escaped by changing profiles")
	}
}
func TestMissingFieldsAndUnits(t *testing.T) {
	for _, k := range fields() {
		r := exampleRecord("missing-field")
		delete(r, k)
		if Validate([]Record{r}).Valid {
			t.Fatalf("missing %s not detected", k)
		}
	}
	r := exampleRecord("units")
	r["time_unit"] = "ms"
	if Validate([]Record{r}).Valid {
		t.Fatal("mixed units accepted")
	}
	r = exampleRecord("extra-unit")
	r["server_ms"] = 1
	if Validate([]Record{r}).Valid {
		t.Fatal("ambiguous additional unit")
	}
}
func TestErrorClassificationNeverCountsFailure(t *testing.T) {
	for _, status := range []string{"runtime_error", "panic", "unsupported_configuration", "timeout", "cancelled", "not_started"} {
		r := exampleRecord(status)
		r["execution_status"] = status
		r["error_message"] = "SYNTHETIC diagnostic"
		r["wrong_output"] = missing
		r["accepted"] = missing
		r["attack_success"] = missing
		if !Validate([]Record{r}).Valid {
			t.Fatal(status)
		}
		s := Analyze([]Record{r})[0]
		if s.Completed != 0 || s.Decisive != 0 || s.Conditional.Value != missing {
			t.Fatalf("%s counted as attack failure", status)
		}
		r["attack_success"] = false
		if Validate([]Record{r}).Valid {
			t.Fatal("error classified false success")
		}
	}
}
func TestSuccessTruthTable(t *testing.T) {
	for _, w := range []bool{false, true} {
		for _, a := range []bool{false, true} {
			r := exampleRecord("truth")
			r["wrong_output"] = w
			r["accepted"] = a
			r["attack_success"] = w && a
			if !Validate([]Record{r}).Valid {
				t.Fatal(w, a)
			}
			r["attack_success"] = !(w && a)
			if Validate([]Record{r}).Valid {
				t.Fatal("invalid AND accepted")
			}
		}
	}
}
func TestPreconditionsAndExplicitDenominators(t *testing.T) {
	rows := []Record{}
	for i, pre := range []any{true, false, missing} {
		r := exampleRecord(string(rune('a' + i)))
		r["precondition_satisfied"] = pre
		rows = append(rows, r)
	}
	s := Analyze(rows)[0]
	if s.Attempted != 3 || s.Completed != 3 || s.Eligible != 1 || s.Decisive != 1 || s.AcceptedIncorrect != 3 || s.Conditional.Numerator != 1 || s.Conditional.Denominator != 1 {
		t.Fatalf("bad denominator %+v", s)
	}
}
func TestMedianIQRType7(t *testing.T) {
	m := metric([]float64{4, 1, 3, 2})
	if m.Median != 2.5 || m.Q1 != 1.75 || m.Q3 != 3.25 || m.IQR != 1.5 {
		t.Fatalf("bad quartiles %+v", m)
	}
	if metric(nil).Median != missing {
		t.Fatal("empty sample fabricated")
	}
	if metric([]float64{8}).IQR != float64(0) {
		t.Fatal("single sample IQR")
	}
}
func TestHEAndKeyProfilesAndRunPartitions(t *testing.T) {
	r := exampleRecord("a")
	rows := []Record{r}
	for i, k := range []string{"parameter_profile", "evaluation_key_profile", "run_id", "data_origin", "timing_boundary"} {
		x := clone(r)
		x["trial_id"] = string(rune('b' + i))
		switch k {
		case "parameter_profile":
			x[k] = "PN13QP218"
		case "evaluation_key_profile":
			x[k] = "extended"
		case "run_id":
			x[k] = "another-run"
		case "data_origin":
			x[k] = "fresh_measurement"
		case "timing_boundary":
			x[k] = map[string]any{"definition": "a different measurement boundary", "included_stages": []any{"evaluation"}}
		}
		rows = append(rows, x)
	}
	if len(Analyze(rows)) != 6 {
		t.Fatal("incompatible records pooled")
	}
	a, _ := comparisonKey(r, false)
	for _, x := range rows[1:] {
		b, _ := comparisonKey(x, false)
		if a == b {
			t.Fatal("incompatible comparisons pooled")
		}
	}
}
func TestAmbiguousBoundariesBlockPlots(t *testing.T) {
	r := exampleRecord("boundary")
	r["timing_boundary"] = "server only"
	if _, ok := comparisonKey(r, false); ok {
		t.Fatal("ambiguous boundary accepted")
	}
	v := Validate([]Record{r})
	if !v.Valid {
		t.Fatal("missing measurement should be diagnostic, not invented")
	}
	found := false
	for _, i := range v.Issues {
		found = found || i.Field == "timing_boundary"
	}
	if !found {
		t.Fatal("boundary issue absent")
	}
}
func TestPerformanceRepetitionTargets(t *testing.T) {
	for _, tc := range []struct{ n, target int }{{8, 20}, {64, 20}, {128, 10}} {
		rows := []Record{}
		for i := 0; i < tc.target; i++ {
			r := exampleRecord(string(rune('A' + i)))
			r["experiment_category"] = "performance"
			r["wrong_output"] = false
			r["attack_success"] = false
			r["mathematical_precondition"] = "none"
			r["input_dimensions"] = map[string]any{"n": tc.n}
			rows = append(rows, r)
		}
		s := Analyze(rows)[0]
		if s.Target != tc.target || s.TargetStatus != "met" {
			t.Fatal(s)
		}
		if Analyze(rows[:len(rows)-1])[0].TargetStatus != "unmet" {
			t.Fatal("target not enforced")
		}
	}
}
func TestWarmupExclusionAndCountSources(t *testing.T) {
	r := exampleRecord("warmup")
	r["is_warmup"] = true
	s := Analyze([]Record{r})[0]
	if s.Attempted != 0 || s.Warmups != 1 || s.Metrics["total_time_ns"].N != 0 {
		t.Fatal("warmup counted")
	}
	r["operation_count_source"] = missing
	if Validate([]Record{r}).Valid {
		t.Fatal("count source missing")
	}
}
func TestSketchAndSecurityAssertions(t *testing.T) {
	r := exampleRecord("sketch")
	r["implementation"] = "private_sketch"
	r["sketch_p"] = 65537
	r["sketch_r"] = 10
	r["sketch_Q_auth"] = 4294967296
	if !Validate([]Record{r}).Valid {
		t.Fatal("valid sketch assumptions")
	}
	r["sketch_r"] = 1
	if Validate([]Record{r}).Valid {
		t.Fatal("r=1 reported as r=10")
	}
	r = exampleRecord("security")
	r["he_security_verified_bits"] = 128
	if Validate([]Record{r}).Valid {
		t.Fatal("target security promoted without evidence")
	}
}
func TestPlotGenerationAndNoOverwrite(t *testing.T) {
	d := filepath.Join(t.TempDir(), "report")
	rows := fixtureRows()
	if e := GenerateReport(rows, d); e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(d)
	if e != nil {
		t.Fatal(e)
	}
	counts := map[string]int{}
	for _, f := range files {
		counts[filepath.Ext(f.Name())]++
		if strings.HasSuffix(f.Name(), ".svg") {
			b, e := os.ReadFile(filepath.Join(d, f.Name()))
			if e != nil || !strings.Contains(string(b), "SYNTHETIC EXAMPLES") {
				t.Fatal("plot lacks synthetic label")
			}
		}
	}
	if counts[".svg"] == 0 || counts[".pdf"] == 0 || counts[".csv"] < 3 {
		t.Fatal("plot/source outputs missing", counts)
	}
	if e = GenerateReport(rows, d); e == nil {
		t.Fatal("existing output overwritten")
	}
	b, e := os.ReadFile(filepath.Join(d, "summary.json"))
	var s []Summary
	if e != nil || json.Unmarshal(b, &s) != nil || len(s) == 0 {
		t.Fatal("summary missing")
	}
}
func TestOperatorCommandIsDataOnly(t *testing.T) { // CLI is restricted to named offline operations.
	if e := run([]string{"attack"}); e == nil {
		t.Fatal("experiment command accepted")
	}
	r := exampleRecord("numeric-string")
	r["seed"] = "123"
	p := filepath.Join(t.TempDir(), "seed.csv")
	if e := WriteCSV(p, []Record{r}); e != nil {
		t.Fatal(e)
	}
	rs, e := ReadRecords(p)
	if e != nil || rs[0]["seed"] != "123" {
		t.Fatal("CSV changed seed type")
	}
}

func TestUnknownIdentityNeverPoolsTrials(t *testing.T) {
	a := exampleRecord("a")
	b := clone(a)
	b["trial_id"] = "b"
	a["parameter_profile"] = missing
	b["parameter_profile"] = missing
	if len(Analyze([]Record{a, b})) != 2 {
		t.Fatal("unknown HE identities pooled")
	}
}
func TestMixedOperationSources(t *testing.T) {
	r := exampleRecord("mixed")
	sources := map[string]any{}
	for _, k := range []string{"rotation_count", "ciphertext_multiplication_count", "plaintext_multiplication_count", "addition_count"} {
		sources[k] = "measured"
	}
	sources["plaintext_multiplication_count"] = "analytical"
	r["operation_count_source"] = sources
	if !Validate([]Record{r}).Valid {
		t.Fatal("valid mixed-source annotations rejected")
	}
	delete(sources, "addition_count")
	if Validate([]Record{r}).Valid {
		t.Fatal("unclassified known counter accepted")
	}
}
func TestMetadataLinkage(t *testing.T) {
	r := exampleRecord("meta")
	r["data_origin"] = "fresh_measurement"
	m := Record{"schema_version": "dataseal.environment.v1", "metadata_id": r["metadata_id"], "machine_id": r["machine_id"]}
	p := filepath.Join(t.TempDir(), "meta.json")
	if e := WriteJSON(p, m); e != nil {
		t.Fatal(e)
	}
	v, e := withMetadata([]Record{r}, Validate([]Record{r}), p)
	if e != nil || !v.Valid {
		t.Fatal(e, v)
	}
	r["machine_id"] = "other-computer"
	v, e = withMetadata([]Record{r}, Validate([]Record{r}), p)
	if e != nil || v.Valid {
		t.Fatal("different-machine metadata linked")
	}
}
func TestJSONLAndMalformedCSV(t *testing.T) {
	r := exampleRecord("line")
	p := filepath.Join(t.TempDir(), "data.jsonl")
	if e := exclusive(p, []byte(canonical(r)+"\n")); e != nil {
		t.Fatal(e)
	}
	rs, e := ReadRecords(p)
	if e != nil || len(rs) != 1 {
		t.Fatal(e)
	}
	p = filepath.Join(t.TempDir(), "bad.csv")
	if e = exclusive(p, []byte("trial_id,trial_id\na,b\n")); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadRecords(p); e == nil {
		t.Fatal("duplicate CSV header accepted")
	}
}

func TestExperimentAIndependentInputDenominator(t *testing.T) {
	a := exampleRecord("first")
	a["sample_mode"] = "independent"
	a["independent_input"] = true
	a["input_digest_sha256"] = strings.Repeat("a", 64)
	b := clone(a)
	b["trial_id"] = "re-encryption"
	b["accepted"] = false
	b["attack_success"] = false
	if v := Validate([]Record{a, b}); !v.Valid {
		t.Fatal(v.Issues)
	}
	s := Analyze([]Record{a, b})[0]
	if s.Attempted != 2 || s.DistinctPlaintextInputs != 1 || s.IndependentInputTrials != 1 || s.IndependentConditional.Denominator != 1 || s.IndependentConditional.Numerator != 1 {
		t.Fatalf("repeated input counted independent: %+v", s)
	}
	a["sample_mode"] = "fixed"
	b["sample_mode"] = "fixed"
	a["independent_input"] = false
	b["independent_input"] = false
	s = Analyze([]Record{a, b})[0]
	if s.IndependentInputTrials != 0 || s.IndependentConditional.Value != missing {
		t.Fatal("fixed ciphertext retries counted independent")
	}
}
func TestIndependentDenominatorDoesNotSelectSuccessfulRetry(t *testing.T) {
	a := exampleRecord("first-error")
	a["sample_mode"] = "independent"
	a["independent_input"] = true
	a["input_digest_sha256"] = strings.Repeat("b", 64)
	a["execution_status"] = "panic"
	a["error_message"] = "synthetic exception"
	a["wrong_output"] = missing
	a["accepted"] = missing
	a["attack_success"] = missing
	b := clone(a)
	b["trial_id"] = "retry"
	b["execution_status"] = "completed"
	b["error_message"] = missing
	b["wrong_output"] = true
	b["accepted"] = true
	b["attack_success"] = true
	s := Analyze([]Record{a, b})[0]
	if s.IndependentInputTrials != 1 || s.IndependentConditional.Denominator != 0 || s.IndependentConditional.Value != missing {
		t.Fatal("successful retry selected as independent evidence")
	}
}
