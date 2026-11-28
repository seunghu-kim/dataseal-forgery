package attackrun

import (
	"crypto/sha256"
	"dsfgo/bfvpack"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

type RunSummary struct {
	Records, Evaluations  int
	ExecutionStatuses     map[string]int
	IndependentInputUnits int
	ObservationUnit       string
}

func readMetadata(path, repository string) (Record, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var m Record
	if e = json.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	if m["schema_version"] != "dataseal.environment.v1" {
		return nil, fmt.Errorf("current dataseal.environment.v1 metadata is required")
	}
	host, e := os.Hostname()
	if e != nil {
		return nil, e
	}
	if m["machine_id"] != host {
		return nil, fmt.Errorf("metadata machine_id differs from this computer")
	}
	if id, ok := m["metadata_id"].(string); !ok || id == "" || id == Missing {
		return nil, fmt.Errorf("metadata ID missing")
	}
	git, e := exec.Command("git", "-C", repository, "--no-optional-locks", "rev-parse", "HEAD").Output()
	if e != nil {
		return nil, e
	}
	recorded, ok := m["git_commit"].(map[string]interface{})
	if !ok || recorded["stdout_stderr"] != strings.TrimSpace(string(git)) {
		return nil, fmt.Errorf("metadata Git SHA differs from current checkout")
	}
	stamp, ok := m["timestamp_utc"].(string)
	if !ok {
		return nil, fmt.Errorf("metadata timestamp missing")
	}
	if _, e = time.Parse(time.RFC3339Nano, stamp); e != nil {
		return nil, e
	}
	if cmd, ok := m["exact_experiment_command_operator_supplied"].(string); !ok || cmd == "" {
		return nil, fmt.Errorf("metadata must record the exact operator experiment command")
	} else if strings.HasPrefix(strings.ToUpper(cmd), "NOT EXECUTED:") || strings.Contains(cmd, "OPERATOR MUST SUPPLY") {
		return nil, fmt.Errorf("metadata contains a documentation/validation placeholder, not an experiment command; collect new metadata first")
	}
	return m, nil
}
func checkPlanMetadata(c Config, m Record) error {
	if m["warmup_count_operator_supplied"] != float64(c.Warmups) || m["repetition_count_operator_supplied"] != float64(c.Trials) {
		return fmt.Errorf("metadata warmup/repetition counts differ from collection flags; capture new metadata for this run")
	}
	profiles, ok := m["bfv_parameter_profiles_operator_supplied"].([]interface{})
	if !ok {
		return fmt.Errorf("metadata BFV profile declaration missing")
	}
	for _, p := range profiles {
		if p == "PN14QP438" {
			return nil
		}
	}
	return fmt.Errorf("metadata must include the unchanged PN14QP438 profile")
}
func sourceHashes(repository string) (Record, error) {
	out := Record{}
	roots := []string{"experiments/lattigo/attackrun", "experiments/lattigo/cmd/attackeval", "experiments/lattigo/attacks", "experiments/lattigo/dataseal", "experiments/lattigo/bfvpack"}
	for _, root := range roots {
		e := filepath.WalkDir(filepath.Join(repository, root), func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			h := sha256.Sum256(b)
			relative, e := filepath.Rel(repository, path)
			if e != nil {
				return e
			}
			out[filepath.ToSlash(relative)] = hex.EncodeToString(h[:])
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
func fileHash(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Run(c Config) (RunSummary, error) {
	summary := RunSummary{ExecutionStatuses: map[string]int{}, ObservationUnit: "records are per verifier; paired_ciphertext_id shares an execution; input hashes, not encryption randomness, identify distinct inputs"}
	if e := c.Validate(); e != nil {
		return summary, e
	}
	s, e := loadSchema(c.Schema)
	if e != nil {
		return summary, e
	}
	metadata, e := readMetadata(c.Metadata, c.Repository)
	if e != nil {
		return summary, e
	}
	if e = checkPlanMetadata(c, metadata); e != nil {
		return summary, e
	}
	if info, e := os.Stat(c.Validator); e != nil || info.IsDir() {
		return summary, fmt.Errorf("existing offline validator executable unavailable: %s", c.Validator)
	}
	if e = os.MkdirAll(filepath.Dir(c.Output), 0755); e != nil {
		return summary, e
	}
	if e = os.Mkdir(c.Output, 0755); e != nil {
		return summary, fmt.Errorf("output must be a NEW directory: %w", e)
	}
	if e = writeNew(filepath.Join(c.Output, "environment.json"), metadata); e != nil {
		return summary, e
	}
	hashes, e := sourceHashes(c.Repository)
	if e != nil {
		return summary, e
	}
	seeds := append([]uint64{}, c.Seeds...)
	warmSeeds := []uint64{}
	if c.Mode == "independent" {
		if len(seeds) == 0 {
			seeds, e = randomSeeds(c.Trials)
			if e != nil {
				return summary, e
			}
		}
		warmSeeds, e = randomSeeds(c.Warmups)
		if e != nil {
			return summary, e
		}
	} else {
		seeds = make([]uint64, c.Trials)
		warmSeeds = make([]uint64, c.Warmups)
	}
	ctx := bfvpack.NewContext()
	params := ctx.Params
	if e = writeNew(filepath.Join(c.Output, "parameter-manifest.json"), Record{"profile": "PN14QP438", "N": params.N(), "t": params.T(), "Q_primes": params.Q(), "P_primes": params.P(), "LogQP": params.LogQP(), "sigma": params.Sigma(), "source": "actual pinned bfvpack.NewContext parameters", "he_security_target_bits": 128, "he_security_verified_bits": Missing}); e != nil {
		return summary, e
	}
	build, _ := debug.ReadBuildInfo()
	var recordedSeeds, recordedWarmSeeds interface{} = Missing, Missing
	if c.Mode == "independent" {
		recordedSeeds, recordedWarmSeeds = seeds, warmSeeds
	}
	evidenceHashes := Record{}
	for label, path := range map[string]string{"schema": c.Schema, "offline_validator": c.Validator, "input_metadata": c.Metadata} {
		hash, err := fileHash(path)
		if err != nil {
			return summary, err
		}
		evidenceHashes[label] = Record{"path": absolute(path), "sha256": hash}
	}
	if e = writeNew(filepath.Join(c.Output, "collection-tools.json"), evidenceHashes); e != nil {
		return summary, e
	}
	if e = writeNew(filepath.Join(c.Output, "run.json"), Record{"run_id": c.RunID, "timestamp_utc": time.Now().UTC().Format(time.RFC3339Nano), "config": c, "root_input_seeds": recordedSeeds, "warmup_input_seeds": recordedWarmSeeds, "root_seed_source": seedSource(c), "input_sampling": "fixed/reproduction are never independent-input trials; independent mode uses domain-separated seeded input generation and digest deduplication", "gomaxprocs_measured": runtime.GOMAXPROCS(0), "go_runtime_version": runtime.Version(), "measurement_clock": attackClockInfo(), "timing_boundary_version": "A-attack-QPC-v1", "build_info": build, "source_sha256": hashes, "exact_operator_command": metadata["exact_experiment_command_operator_supplied"], "invocation_argv": c.Arguments, "timing_boundary": timingBoundary(), "legacy_collector": "--collect is the only collection mode; positional invocation is not accepted"}); e != nil {
		return summary, e
	}
	journal, e := os.OpenFile(filepath.Join(c.Output, "trials.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return summary, e
	}
	defer journal.Close()
	encoder := json.NewEncoder(journal)
	independent := map[string]bool{}
	emit := func(r Record) error {
		if e := encoder.Encode(r); e != nil {
			return e
		}
		if e := journal.Sync(); e != nil {
			return e
		}
		summary.Records++
		status, _ := r["execution_status"].(string)
		summary.ExecutionStatuses[status]++
		if r["independent_input"] == true && !isWarmup(r) {
			independent[fmt.Sprint(r["workload"])+":"+fmt.Sprint(r["input_digest_sha256"])] = true
		}
		return nil
	}
	seen := map[string]string{}
	for pass, roots := range [][]uint64{warmSeeds, seeds} {
		for i, seed := range roots {
			for si, size := range c.Sizes {
				for _, scenario := range c.Scenarios {
					group := fmt.Sprintf("%s-p%d-t%04d-s%02d-%s", c.RunID, pass, i, si, scenario)
					for _, profile := range c.Profiles {
						t := task{Scenario: scenario, Profile: profile, ID: group + "-" + profile, InputGroup: group, Size: size, Seed: seed, Warmup: pass == 0}
						summary.Evaluations++
						if e = runTimedTask(ctx, s, c, t, metadata["machine_id"].(string), metadata["metadata_id"].(string), seen, emit); e != nil {
							return summary, e
						}
					}
				}
			}
			if c.NegativeControls {
				group := fmt.Sprintf("%s-p%d-t%04d-negative", c.RunID, pass, i)
				t := task{Scenario: "matmul_kernel", Profile: "negative_control", ID: group, InputGroup: group, Size: Size{3, 2, 2, 5}, Seed: seed, Warmup: pass == 0, Negative: true}
				summary.Evaluations++
				if e = runTimedTask(ctx, s, c, t, metadata["machine_id"].(string), metadata["metadata_id"].(string), seen, emit); e != nil {
					return summary, e
				}
			}
		}
	}
	if c.IncludeUnsupported {
		t := task{Scenario: "square_rescale", Profile: "not_applicable", ID: c.RunID + "-zero-product-unsupported", Size: c.Sizes[0]}
		r := baseRecord(s, c, t, metadata["machine_id"].(string), metadata["metadata_id"].(string))
		r["workload"] = "square_zero_product"
		r["workload_definition"] = Record{"expression": "conditional zero-product squaring; no existing Lattigo/BFV implementation"}
		r["verifier"] = "dataseal_square"
		r["execution_status"] = "unsupported_configuration"
		r["error_message"] = "no Lattigo/BFV zero-product attack implementation"
		r["unsupported_capability_reason"] = "implementation absent, not an evaluation-key diagnosis"
		r["independent_input"] = false
		unsupportedInputMetadata(r)
		if e = emit(r); e != nil {
			return summary, e
		}
	}
	summary.IndependentInputUnits = len(independent)
	if e = writeNew(filepath.Join(c.Output, "run-summary.json"), summary); e != nil {
		return summary, e
	}
	if e = journal.Close(); e != nil {
		return summary, e
	}
	// The offline validator runs outside all experimental timers.
	cmd := exec.Command(absolute(c.Validator), "validate", "--input", absolute(filepath.Join(c.Output, "trials.jsonl")), "--metadata", absolute(filepath.Join(c.Output, "environment.json")), "--out", absolute(filepath.Join(c.Output, "validation.json")))
	stdout, e := cmd.CombinedOutput()
	if we := writeNew(filepath.Join(c.Output, "validation-process.json"), Record{"argv": cmd.Args, "stdout_stderr": string(stdout), "error": errorText(e)}); we != nil {
		return summary, we
	}
	if e != nil {
		return summary, fmt.Errorf("raw records preserved but offline schema validation failed: %w", e)
	}
	return summary, nil
}
func errorText(e error) interface{} {
	if e == nil {
		return Missing
	}
	return e.Error()
}
func isWarmup(r Record) bool { b, _ := r["is_warmup"].(bool); return b }
func seedSource(c Config) string {
	if c.Mode != "independent" {
		return "fixed literals or existing deterministic reproduction seeds; root seeds unused"
	}
	if len(c.Seeds) > 0 {
		return "explicit operator uint64 seeds; independence unverified"
	}
	return "fresh crypto/rand uint64 roots, checked for duplicates within measured seed list"
}
