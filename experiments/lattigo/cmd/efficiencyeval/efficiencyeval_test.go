package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const tpe = 18014398507614209 // PE plaintext modulus (54-bit)

func repoRoot(t *testing.T) string {
	t.Helper()
	r, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func synthetic(freq int64) []stageObs {
	// S1..S9 with S3, S7 not applicable; 1 tick gaps between stages.
	tick := int64(1000)
	st := []stageObs{}
	for _, name := range stageNames {
		if name == "authentication_preparation" || name == "verifier_precomputation" {
			st = append(st, stageObs{Name: name, Status: "not_applicable", Reason: "test"})
			continue
		}
		st = append(st, stageObs{Name: name, Status: "measured", Begin: tick, End: tick + 50})
		tick += 51
	}
	return st
}

func TestSummarizeAggregates(t *testing.T) {
	freq := int64(10000000)
	sum, problems := summarize(synthetic(freq), freq)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	// 7 measured stages x 50 ticks, 6 gaps of 1 tick
	if sum["e2e_ticks"] != int64(7*50+6) || sum["stage_sum_ticks"] != int64(350) || sum["gap_ticks"] != int64(6) {
		t.Fatalf("aggregates wrong: %v", sum)
	}
	if sum["fair_e2e_ns"] != int64(356*100) || sum["fair_gap_ns"] != int64(600) || sum["sum_identity_exact_ns"] != true {
		t.Fatalf("ns conversion wrong: %v", sum)
	}
	// client = (S6.begin - t0) + (t_end - S6.end); S6 is the 5th measured stage
	st := synthetic(freq)
	var s6 stageObs
	for _, s := range st {
		if s.Name == "server_evaluation" {
			s6 = s
		}
	}
	wantClient := ticksToNs((s6.Begin-1000)+(st[len(st)-1].End-s6.End), freq)
	if sum["fair_client_ns"] != wantClient || sum["fair_server_ns"] != int64(5000) {
		t.Fatalf("client/server wrong: %v", sum)
	}
	// derived split: S3 and S7 are N/A here; 50 ticks = 5000 ns per stage
	if sum["setup_ns"] != int64(10000) || sum["prep_ns"] != int64(5000) || sum["client_online_ns"] != int64(15000) || sum["server_ns"] != int64(5000) {
		t.Fatalf("derived split wrong: %v", sum)
	}
	if sum["setup_ns"].(int64)+sum["prep_ns"].(int64)+sum["client_online_ns"].(int64)+sum["server_ns"].(int64)+sum["fair_gap_ns"].(int64) != sum["fair_e2e_ns"].(int64) {
		t.Fatalf("derived split + gap != E2E: %v", sum)
	}
}

// Invalid timing (nonpositive, overlapping, misordered, missing or incomplete
// stages) is reported as gate problems.
func TestSummarizeRejectsInvalidTiming(t *testing.T) {
	freq := int64(10000000)
	mut := map[string]func([]stageObs) []stageObs{
		"zero duration":  func(s []stageObs) []stageObs { s[0].End = s[0].Begin; return s },
		"negative":       func(s []stageObs) []stageObs { s[1].End = s[1].Begin - 5; return s },
		"overlap":        func(s []stageObs) []stageObs { s[3].Begin = s[1].Begin; return s },
		"order":          func(s []stageObs) []stageObs { s[0], s[1] = s[1], s[0]; return s },
		"missing server": func(s []stageObs) []stageObs { s[5].Status = "not_applicable"; return s },
		"incomplete":     func(s []stageObs) []stageObs { s[7].Status = "incomplete"; return s },
		"missing stage":  func(s []stageObs) []stageObs { return s[:8] },
	}
	for name, m := range mut {
		if _, problems := summarize(m(synthetic(freq)), freq); len(problems) == 0 {
			t.Fatalf("%s: expected gate problems", name)
		}
	}
}

func TestTicksToNs(t *testing.T) {
	cases := []struct{ d, f, want int64 }{{1, 10000000, 100}, {10000000, 10000000, 1000000000}, {3, 3000000, 1000}, {7, 3579545, 1955}}
	for _, c := range cases {
		if got := ticksToNs(c.d, c.f); got != c.want {
			t.Fatalf("ticksToNs(%d,%d)=%d want %d", c.d, c.f, got, c.want)
		}
	}
}

// On the real clock, stages are positive, monotonic and satisfy the sum identity.
func TestRealQPCStages(t *testing.T) {
	freq, err := clockFrequency()
	if err != nil {
		t.Skip(err)
	}
	tm := newStageTimer(qpcTicks, false)
	work := func() {
		x := 0
		for i := 0; i < 2000000; i++ {
			x += i ^ (x >> 3)
		}
		_ = x
	}
	for _, name := range stageNames {
		if name == "authentication_preparation" {
			tm.skip(name, "test")
			continue
		}
		tm.stage(name, work)
	}
	sum, problems := summarize(tm.stages, freq)
	if len(problems) != 0 {
		t.Fatalf("real QPC problems: %v", problems)
	}
	t.Logf("QPC %d Hz: e2e %v ns, gap %v ns", freq, sum["fair_e2e_ns"], sum["fair_gap_ns"])
}

// The collector refuses to start unless GOMAXPROCS=1.
func TestGOMAXPROCSGate(t *testing.T) {
	prev := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(prev)
	err := run([]string{"--repo", repoRoot(t), "--out", filepath.Join(t.TempDir(), "x"), "--metadata", "none.json", "--run-id", "test", "--pe-t", "18014398507614209"})
	if err == nil || !strings.Contains(err.Error(), "GOMAXPROCS must be 1") {
		t.Fatalf("expected GOMAXPROCS refusal, got %v", err)
	}
}

// Existing output directories and files are never overwritten.
func TestOverwriteRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if err := createOutDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := createOutDir(dir); err == nil {
		t.Fatalf("existing output directory accepted")
	}
	p := filepath.Join(dir, "run.json")
	if err := writeNew(p, bRecord{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(p, bRecord{"a": 2}); err == nil {
		t.Fatalf("existing file overwritten")
	}
}

func TestCellsVeritasNativeOnly(t *testing.T) {
	c := config{methods: []string{"bfv_only", "veritas_rep"}, packings: []string{"controlled", "native"}}
	got := cells(c)
	want := [][2]string{{"bfv_only", "controlled"}, {"bfv_only", "native"}, {"veritas_rep", "native"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cells %v", got)
	}
	c.packings = []string{"controlled"}
	if got := cells(c); len(got) != 1 {
		t.Fatalf("VERITAS must be native only: %v", got)
	}
}

// Parameters and source hashes carry every required provenance item.
func TestProvenanceRecords(t *testing.T) {
	root := repoRoot(t)
	schemaPath, validator := validatorPaths(root)
	if _, err := os.Stat(validator); err != nil {
		t.Skipf("validator not built (see scripts/build_and_test.sh): %v", err)
	}
	c := config{repo: root, schema: schemaPath, validator: validator, methods: []string{"bfv_only", "dataseal_original", "dataseal_strengthened", "private_sketch", "veritas_rep", "veritas_pe", "veritas_pe_t17"}, peT: tpe}
	p, err := parametersRecord(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	s := string(b)
	for _, want := range []string{`"T":65537`, `"T":18014398507614209`, `"replication_lambda":64`, `"block_size":8`, `"block_size":64`, "stride", "public-key", "rotation keys only", "forgery_bound", "no verification oracle", "public mask", "shared_across_row_blocks", "per_row_block", "security_below_target", "he_security", "lattice-estimator not run", "128-bit classical"} {
		if !strings.Contains(s, want) {
			t.Fatalf("parameters.json lacks %q", want)
		}
	}
	h, err := sourceHashes(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"experiments/lattigo/veritas/matmul.go", "experiments/lattigo/bfvpack/meter.go", "experiments/lattigo/bfvpack/tiled.go", "experiments/lattigo/cmd/efficiencyeval/main.go", "external/veritas/vche_1/encoder.go", "external/veritas/vche_2/evaluator.go"} {
		if _, ok := h[f]; !ok {
			t.Fatalf("source hash missing %s", f)
		}
	}
	if _, err := checkVeritasPin(root); err != nil {
		t.Fatalf("external veritas pin: %v", err)
	}
}

func TestPEModulusChecks(t *testing.T) {
	rec, err := checkPEModulus(tpe)
	if err != nil {
		t.Fatalf("approved modulus rejected: %v", err)
	}
	if rec["largest_valid_below_smallest_QP_prime"] != true || rec["bits"] != 54 {
		t.Fatalf("approved modulus record: %v", rec)
	}
	if _, err := checkPEModulus(72057594037370881); err == nil {
		t.Fatalf("T56 must be rejected (not below every Q/P prime)")
	}
	if _, err := checkPEModulus(288230376155250689); err == nil {
		t.Fatalf("T58 must be rejected on PN14 (t > Q[0])")
	}
	if _, err := checkPEModulus(72057594038321153); err == nil {
		t.Fatalf("q0-colliding T must be rejected")
	}
}
