// Command efficiencyeval measures matrix multiplication and the elementwise,
// input-reuse and composition workloads under one timing boundary (stages
// S1..S9, GOMAXPROCS=1).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil && err != flag.ErrHelp {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("efficiencyeval", flag.ContinueOnError)
	c := config{}
	fs.StringVar(&c.repo, "repo", "", "repository root (required)")
	fs.StringVar(&c.out, "out", "", "NEW output directory (required; refused if it exists)")
	fs.StringVar(&c.meta, "metadata", "", "fresh environment JSON from the validator's environment command (required)")
	fs.StringVar(&c.schema, "schema", "", "dataseal.trial.v1 schema.json (default: tools/validator)")
	fs.StringVar(&c.validator, "validator", "", "validator executable (default: tools/validator)")
	fs.StringVar(&c.id, "run-id", "", "run ID (required)")
	fs.StringVar(&c.modfile, "modfile", "", "modfile used for the build (recorded and hashed)")
	sizes := fs.String("sizes", "8,16,32", "square matmul sizes")
	methods := fs.String("methods", "bfv_only,dataseal_original,dataseal_strengthened,private_sketch,veritas_rep,veritas_pe", "methods (veritas_pe_t17 optional)")
	packings := fs.String("packings", "controlled,native", "BFV packings; VERITAS always native")
	fs.IntVar(&c.trials, "trials", 20, "main trials per cell")
	fs.IntVar(&c.warmups, "warmups", 1, "warmup trials per cell (persisted, is_warmup=true)")
	fs.Uint64Var(&c.seed, "seed", 1, "fixture seed: A=seed, B=seed+1")
	fs.Uint64Var(&c.peT, "pe-t", 0, "PE plaintext modulus for veritas_pe (required when selected)")
	fs.BoolVar(&c.stopOnError, "stop-on-error", false, "stop after the first failing trial (record preserved)")
	fs.BoolVar(&c.memstats, "pilot-memstats", false, "pilot only: ReadMemStats at every stage boundary (inside the timeline)")
	fs.StringVar(&c.workload, "workload", "matmul", "matmul | element-add | element-square | reuse | compose")
	fs.IntVar(&c.programs, "programs", 1, "reuse only: number of public programs per encrypted input (1,2,4,8)")
	fs.IntVar(&c.sketchRows, "sketch-rows", 0, "matmul private_sketch only: sketch rows r (0 = RowsFor(65537,128,2^32)=10; r below that is cost comparison only)")
	if e := fs.Parse(args); e != nil {
		return c, e
	}
	if fs.NArg() != 0 || c.repo == "" || c.out == "" || c.meta == "" || c.id == "" || c.trials < 1 || c.warmups < 0 {
		return c, fmt.Errorf("required: --repo --out --metadata --run-id; positive --trials, nonnegative --warmups")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`).MatchString(c.id) {
		return c, fmt.Errorf("invalid run ID")
	}
	for _, s := range splitList(*sizes) {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 128 {
			return c, fmt.Errorf("sizes must be integers in [1,128]")
		}
		c.sizes = append(c.sizes, n)
	}
	c.methods = splitList(*methods)
	c.packings = splitList(*packings)
	seen := map[string]bool{}
	for _, m := range c.methods {
		if !bfvMethods[m] && !veritasMethods[m] || seen[m] {
			return c, fmt.Errorf("unknown or duplicate method %q", m)
		}
		seen[m] = true
		if m == "veritas_pe" && c.peT == 0 {
			return c, fmt.Errorf("--pe-t is required for veritas_pe")
		}
	}
	for _, p := range c.packings {
		if p != "controlled" && p != "native" {
			return c, fmt.Errorf("packings must be controlled and/or native")
		}
	}
	if len(c.sizes) == 0 || len(c.methods) == 0 || len(c.packings) == 0 {
		return c, fmt.Errorf("empty sizes/methods/packings")
	}
	switch c.workload {
	case "matmul", "compose":
	case "element-add", "element-square":
		for _, n := range c.sizes {
			if n > 64 {
				return c, fmt.Errorf("elementwise sizes limited to n<=64")
			}
		}
	case "reuse":
		if c.programs != 1 && c.programs != 2 && c.programs != 4 && c.programs != 8 {
			return c, fmt.Errorf("reuse --programs must be 1,2,4,8")
		}
		for _, n := range c.sizes {
			if n > 16 {
				return c, fmt.Errorf("reuse limited to n<=16")
			}
		}
	default:
		return c, fmt.Errorf("unknown workload %q", c.workload)
	}
	if c.workload != "reuse" && c.programs != 1 {
		return c, fmt.Errorf("--programs applies to the reuse workload only")
	}
	if c.sketchRows < 0 {
		return c, fmt.Errorf("--sketch-rows must be >= 0")
	}
	if c.sketchRows > 0 && (c.workload != "matmul" || !seen["private_sketch"]) {
		return c, fmt.Errorf("--sketch-rows applies to the matmul workload with private_sketch only")
	}
	var e error
	if c.repo, e = filepath.Abs(c.repo); e != nil {
		return c, e
	}
	defSchema, defValidator := validatorPaths(c.repo)
	if c.schema == "" {
		c.schema = defSchema
	}
	if c.validator == "" {
		c.validator = defValidator
	}
	return c, nil
}

// cells lists (method, packing) pairs: BFV methods x packings; VERITAS native only.
func cells(c config) [][2]string {
	out := [][2]string{}
	native := false
	for _, p := range c.packings {
		native = native || p == "native"
	}
	for _, m := range c.methods {
		if bfvMethods[m] && (c.workload == "element-add" || c.workload == "element-square") {
			out = append(out, [2]string{m, "elementwise_common"}) // stride n+1 layout, one packing
		} else if bfvMethods[m] && c.workload == "compose" {
			out = append(out, [2]string{m, "native"})
		} else if bfvMethods[m] {
			for _, p := range c.packings {
				out = append(out, [2]string{m, p})
			}
		} else if c.workload == "compose" || c.workload == "element-add" || c.workload == "element-square" {
			out = append(out, [2]string{m, "native"})
		} else if native {
			out = append(out, [2]string{m, "native"})
		}
	}
	return out
}

func baseRecord(required []string, c config, meta bRecord, method, packing string, n, index int, warm bool) bRecord {
	r := bRecord{}
	for _, k := range required {
		r[k] = bMissing
	}
	profile, _ := profileFor(method, c.peT)
	verifier := method
	if method == "bfv_only" {
		verifier = "none"
	}
	stages := append([]string{}, stageNames...)
	for k, v := range (bRecord{
		"schema_version": "dataseal.trial.v1", "experiment_id": "Experiment-B-fair", "run_id": c.id,
		"trial_id":            fmt.Sprintf("%s-%s%s-%s-n%d-w%t-%d", c.id, workloadTag(c), method, packing, n, warm, index),
		"experiment_category": "performance", "workload": "public_right_matmul", "implementation": method, "verifier": verifier,
		"input_dimensions": bRecord{"n": n, "d": n, "ell": n}, "seed": bRecord{"A": c.seed, "B": c.seed + 1},
		"seed_provenance": "fixed LCG fixture (rnd); HE/authentication randomness not seeded", "sample_mode": "fixed", "independent_input": false,
		"parameter_profile": profile, "evaluation_key_profile": "honest_minimal", "data_origin": "fresh_measurement",
		"machine_id": meta["machine_id"], "metadata_id": meta["metadata_id"], "time_unit": "ns", "is_warmup": warm,
		"mathematical_precondition": "none", "execution_status": "not_started", "error_message": "not started",
		"he_security_target_bits": 128, "he_security_verified_bits": bMissing,
		"workload_definition": bRecord{"expression": "A[n,n]*B[n,n] mod 65537; A confidential, B public", "input_sampling": "fixed LCG fixture; same A/B seeds across methods", "input_reuse": "none; fresh session/input per trial"},
		"batch":               1, "programs_per_trial": 1, "input_reuse_programs": bMissing, "reuse_policy": "no_input_reuse",
		"packing_mode": packing, "timing_boundary_version": boundaryVersion, "gomaxprocs": runtime.GOMAXPROCS(0),
		"timing_boundary": bRecord{"definition": "B-fair-v3 common fresh-session public-right matmul boundary: t0 immediately before HE parameter/context construction; end after the last verify/decode and n x n matrix restoration. Fixture, plaintext reference and layout computation precede t0; serialization, correctness comparison, counts and logging follow t_end.", "included_stages": stages, "version": boundaryVersion, "clock": clockSource, "unit": "ns (converted from raw QPC ticks by integer quotient/remainder)", "client": "(S6.begin - t0) + (t_end - S6.end)", "server": "S6", "gap": "E2E - sum of measured stages", "e2e_from_keygen": "t_end - S2.begin (reference for B-2 total_time_ns definition only)", "derived": "setup_ns=S1+S2+S3, prep_ns=S4, client_online_ns=S5+S7+S8+S9, server_ns=S6 (measured stages only; N/A adds nothing; inter-stage gaps excluded, so setup+prep+client_online+server+gap = E2E)", "direct": "direct_computation_ns: one matrix.Mul before t0, outside S1..S9"},
		"security":        trialSecurity(c, method),
	}) {
		r[k] = v
	}
	// The schema's older timing fields have different meanings; never filled here.
	for _, k := range []string{"total_time_ns", "client_time_ns", "evaluation_time_ns", "key_generation_time_ns", "encryption_time_ns", "decryption_time_ns", "verification_time_ns", "preparation_time_ns", "program_preparation_time_ns", "packing_time_ns", "direct_computation_time_ns", "direct_computation_ns", "setup_ns", "prep_ns", "client_online_ns", "server_ns"} {
		r[k] = bMissing
	}
	return r
}

// workloadTag leaves matmul trial IDs unprefixed and prefixes the other workloads.
func workloadTag(c config) string {
	switch c.workload {
	case "matmul", "":
		return ""
	case "reuse":
		return fmt.Sprintf("reuse%d-", c.programs)
	}
	return c.workload + "-"
}

// createOutDir creates a NEW output directory and refuses an existing one.
func createOutDir(out string) error {
	if e := os.MkdirAll(filepath.Dir(out), 0755); e != nil {
		return e
	}
	if e := os.Mkdir(out, 0755); e != nil {
		return fmt.Errorf("output directory must not exist: %w", e)
	}
	return nil
}

type trialGate struct {
	TrialID  string   `json:"trial_id"`
	Warmup   bool     `json:"is_warmup"`
	Status   string   `json:"execution_status"`
	Passed   bool     `json:"passed"`
	Problems []string `json:"problems"`
}

func runTrial(r bRecord, c config, freq int64, method, packing string, n int) (gate trialGate) {
	tm := newStageTimer(qpcTicks, c.memstats)
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		defer func() {
			if p := recover(); p != nil {
				r["execution_status"] = "panic"
				r["error_message"] = fmt.Sprint(p)
				r["error_stack"] = string(debug.Stack())
				r["error_stage"] = tm.current
				r["accepted"], r["attack_success"], r["wrong_output"] = bMissing, bMissing, bMissing
			}
		}()
		switch {
		case c.workload == "element-add" || c.workload == "element-square":
			runElement(r, tm, freq, method, strings.TrimPrefix(c.workload, "element-"), n, c.seed, c.peT)
		case c.workload == "reuse":
			runReuse(r, tm, freq, method, packing, n, c.programs, c.seed, c.peT)
		case c.workload == "compose":
			runCompose(r, tm, freq, method, n, c.seed)
		case bfvMethods[method]:
			runBFV(r, tm, freq, method, packing, n, c.seed, c.sketchRows)
		default:
			runVeritas(r, tm, freq, method, n, c.seed, c.peT)
		}
		if r["execution_status"] == "not_started" {
			r["execution_status"], r["error_message"] = "completed", bMissing
		}
	}()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	peak, cur, merr := processMemory()
	mem := bRecord{"heap_alloc_after": after.HeapAlloc, "heap_sys_after": after.HeapSys, "sys_after": after.Sys, "total_alloc_delta": after.TotalAlloc - before.TotalAlloc, "num_gc_delta": after.NumGC - before.NumGC, "gc_pause_total_ns_delta": after.PauseTotalNs - before.PauseTotalNs, "process_peak_working_set_bytes": peak, "process_working_set_bytes": cur, "scope": "read after t_end, outside the timeline; process peak is cumulative over the process"}
	if merr != nil {
		mem["process_memory_error"] = merr.Error()
	}
	if c.memstats {
		mem["per_stage_pilot"] = tm.mem
	}
	r["memory"] = mem
	r["fair_substages"] = tm.subRecord(freq)
	gate = trialGate{TrialID: fmt.Sprint(r["trial_id"]), Warmup: r["is_warmup"] == true, Status: fmt.Sprint(r["execution_status"]), Problems: []string{}}
	switch r["execution_status"] {
	case "completed":
		sum, problems := summarize(tm.stages, freq)
		r["fair_timing"] = sum
		for _, k := range []string{"fair_e2e_ns", "fair_client_ns", "fair_server_ns", "fair_gap_ns", "fair_stage_sum_ns", "e2e_from_keygen_ns", "setup_ns", "prep_ns", "client_online_ns", "server_ns"} {
			if v, ok := sum[k]; ok {
				r[k] = v
			} else {
				r[k] = bMissing
			}
		}
		r["fair_timing_gate"] = bRecord{"passed": len(problems) == 0, "problems": problems}
		gate.Problems = append(gate.Problems, problems...)
		if r["wrong_output"] != false {
			gate.Problems = append(gate.Problems, fmt.Sprintf("wrong_output=%v", r["wrong_output"]))
		}
		if r["verifier"] != "none" && r["accepted"] != true {
			gate.Problems = append(gate.Problems, fmt.Sprintf("accepted=%v", r["accepted"]))
		}
	case "unsupported_configuration":
		if r["unsupported_expected"] != true {
			gate.Problems = append(gate.Problems, "unsupported: "+fmt.Sprint(r["error_message"]))
		}
	default:
		sum, _ := summarize(tm.stages, freq)
		r["fair_timing"] = sum
		gate.Problems = append(gate.Problems, fmt.Sprintf("%v at %v: %v", r["execution_status"], r["error_stage"], r["error_message"]))
	}
	gate.Passed = len(gate.Problems) == 0
	return gate
}

func run(args []string) error {
	c, e := parseConfig(args)
	if e != nil {
		return e
	}
	if g := runtime.GOMAXPROCS(0); g != 1 {
		return fmt.Errorf("GOMAXPROCS must be 1 (runtime reports %d); set GOMAXPROCS=1 in the run script", g)
	}
	freq, e := clockFrequency()
	if e != nil {
		return e
	}
	pin, e := checkVeritasPin(c.repo)
	if e != nil {
		return e
	}
	profiles := []string{}
	seenP := map[string]bool{}
	for _, m := range c.methods {
		if p, _ := profileFor(m, c.peT); !seenP[p] {
			seenP[p] = true
			profiles = append(profiles, p)
		}
		if m == "veritas_pe" {
			if _, e := checkPEModulus(c.peT); e != nil {
				return e
			}
		}
	}
	meta, e := checkMetadata(c, profiles)
	if e != nil {
		return e
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if e = readJSON(c.schema, &schema); e != nil {
		return e
	}
	if len(schema.Required) == 0 {
		return fmt.Errorf("empty schema")
	}
	if _, e = os.Stat(c.validator); e != nil {
		return e
	}
	params, e := parametersRecord(c)
	if e != nil {
		return e
	}
	hashes, e := sourceHashes(c)
	if e != nil {
		return e
	}
	head, _ := gitOut(c.repo, "rev-parse", "HEAD")
	status, _ := gitOut(c.repo, "status", "--porcelain=v1", "--untracked-files=all")
	if e = createOutDir(c.out); e != nil {
		return e
	}
	build, _ := debug.ReadBuildInfo()
	env := bRecord{}
	for _, k := range []string{"GOMAXPROCS", "GOGC", "GODEBUG", "GOMEMLIMIT", "GOFLAGS"} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		} else {
			env[k] = "unset"
		}
	}
	runRec := bRecord{"argv": args, "boundary_version": boundaryVersion, "runtime_gomaxprocs": runtime.GOMAXPROCS(0), "runtime_numcpu": runtime.NumCPU(), "runtime_version": runtime.Version(), "go_environment": env, "build_info": build, "clock": bRecord{"source": clockSource, "frequency_hz": freq, "conversion": "integer quotient/remainder of raw ticks"}, "source_sha256": hashes, "repository_head": head, "repository_status_porcelain": status, "external_veritas": pin, "trials": c.trials, "warmups": c.warmups, "sizes": c.sizes, "methods": c.methods, "packings": c.packings, "cells": cells(c), "seed": c.seed, "pe_t": c.peT, "workload": c.workload, "programs": c.programs, "rep_lambda": repLambda, "rep_block": repBlock, "pe_block": peBlock, "bfv_tile_col": tileCol, "order": "warmups first, then main; within each: sizes -> methods -> packings -> trials", "pilot_memstats": c.memstats, "note": "GOMAXPROCS fixed to 1 by the run script and enforced at start; sequential; fixed input repetitions, not independent inputs"}
	for name, v := range map[string]interface{}{"environment.json": meta, "commands.json": bRecord{"operator_command": meta["exact_experiment_command_operator_supplied"], "collector_argv": os.Args}, "parameters.json": params, "run.json": runRec} {
		if e = writeNew(filepath.Join(c.out, name), v); e != nil {
			return e
		}
	}
	f, e := os.OpenFile(filepath.Join(c.out, "trials.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	gates := []trialGate{}
	stopped := false
	started := time.Now().UTC()
loop:
	for _, warm := range []bool{true, false} {
		count := c.trials
		if warm {
			count = c.warmups
		}
		for _, n := range c.sizes {
			for _, cell := range cells(c) {
				for i := 0; i < count; i++ {
					r := baseRecord(schema.Required, c, meta, cell[0], cell[1], n, i, warm)
					r["trial_started_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
					g := runTrial(r, c, freq, cell[0], cell[1], n)
					r["trial_finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
					if e = enc.Encode(r); e != nil {
						return e
					}
					if e = f.Sync(); e != nil {
						return e
					}
					gates = append(gates, g)
					fmt.Printf("%s: %s passed=%t\n", g.TrialID, g.Status, g.Passed)
					if c.stopOnError && !g.Passed {
						stopped = true
						break loop
					}
				}
			}
		}
	}
	f.Close()
	cmd := exec.Command(c.validator, "validate", "--input", filepath.Join(c.out, "trials.jsonl"), "--metadata", filepath.Join(c.out, "environment.json"), "--out", filepath.Join(c.out, "validation.json"))
	vlog, verr := cmd.CombinedOutput()
	if e = os.WriteFile(filepath.Join(c.out, "validator.log"), vlog, 0644); e != nil {
		return e
	}
	failed := 0
	for _, g := range gates {
		if !g.Passed {
			failed++
		}
	}
	summary := bRecord{"boundary_version": boundaryVersion, "started_utc": started.Format(time.RFC3339Nano), "finished_utc": time.Now().UTC().Format(time.RFC3339Nano), "records": len(gates), "failed": failed, "stopped_early": stopped, "offline_validator_ok": verr == nil, "trials": gates}
	if e = writeNew(filepath.Join(c.out, "fair_gates.json"), summary); e != nil {
		return e
	}
	if verr != nil {
		return fmt.Errorf("offline validation failed: %w: %s", verr, vlog)
	}
	if failed > 0 {
		return fmt.Errorf("%d trial(s) failed the timing gates; see fair_gates.json", failed)
	}
	return nil
}
