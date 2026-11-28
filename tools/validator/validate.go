package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

type Issue struct {
	Severity string `json:"severity"`
	Row      int    `json:"row"`
	Field    string `json:"field"`
	Message  string `json:"message"`
}
type Validation struct {
	Valid      bool    `json:"valid"`
	Rows       int     `json:"rows"`
	Issues     []Issue `json:"issues"`
	Partitions int     `json:"separate_analysis_partitions"`
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

func Validate(rows []Record) Validation {
	v := Validation{Valid: true, Rows: len(rows), Issues: []Issue{}}
	add := func(sev string, i int, k, msg string) {
		v.Issues = append(v.Issues, Issue{sev, i + 1, k, msg})
		if sev == "error" {
			v.Valid = false
		}
	}
	if len(rows) == 0 {
		add("error", -1, "dataset", "no trial records supplied")
	}
	seen := map[string]bool{}
	parts := map[string]bool{}
	for i, r := range rows {
		if r == nil {
			add("error", i, "record", "record must be an object")
			continue
		}
		for _, k := range fields() {
			x, ok := r[k]
			if !ok {
				add("error", i, k, "required field absent; use not_measured if unavailable")
			} else if x == nil {
				add("error", i, k, "null is not canonical; use not_measured")
			}
		}
		for _, k := range []string{"experiment_id", "run_id", "trial_id"} {
			if !idPattern.MatchString(text(r[k])) || absent(r[k]) {
				add("error", i, k, "expected stable identifier [A-Za-z0-9_.:-], not a missing value")
			}
		}
		id := canonical([]any{r["experiment_id"], r["run_id"], r["trial_id"]})
		if seen[id] {
			add("error", i, "trial_id", "duplicate composite experiment/run/trial identifier")
		}
		seen[id] = true
		if text(r["schema_version"]) != version {
			add("error", i, "schema_version", "unsupported schema version")
		}
		for _, k := range []string{"experiment_category", "workload", "implementation", "verifier", "parameter_profile", "evaluation_key_profile", "machine_id", "metadata_id"} {
			if absent(r[k]) {
				add("warning", i, k, "missing identity/provenance; cross-method comparison blocked")
			} else if text(r[k]) == "" {
				add("error", i, k, "expected nonempty string")
			}
		}
		cat := text(r["experiment_category"])
		if cat != "attack" && cat != "performance" && cat != "correctness" {
			add("error", i, "experiment_category", "expected attack, performance, or correctness")
		}
		origin := text(r["data_origin"])
		if origin != "synthetic_example" && origin != "fresh_measurement" {
			add("error", i, "data_origin", "declare synthetic_example or fresh_measurement; declaration alone does not prove freshness")
		}
		prof := text(r["evaluation_key_profile"])
		if prof != "honest_minimal" && prof != "extended" && prof != "negative_control" && prof != "not_applicable" && prof != missing {
			add("error", i, "evaluation_key_profile", "unknown profile; do not pool capability profiles")
		}
		if text(r["time_unit"]) != "ns" {
			add("error", i, "time_unit", "all numeric time fields must use nanoseconds (ns); no automatic conversion")
		}
		allTimes := append(append([]string{}, timeFields...), "packing_time_ns", "direct_computation_time_ns", "program_preparation_time_ns")
		for _, k := range append(allTimes, "error_magnitude", "rotation_count", "ciphertext_multiplication_count", "plaintext_multiplication_count", "addition_count", "key_switch_count") {
			x, ok := r[k]
			if !ok || absent(x) {
				continue
			}
			n, ok := number(x)
			if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
				add("error", i, k, "expected finite nonnegative numeric measurement or not_measured")
			}
			if strings.HasSuffix(k, "_count") && ok && n != math.Trunc(n) {
				add("error", i, k, "operation counts must be integral")
			}
		}
		for _, k := range []string{"wrong_output", "accepted", "attack_success", "precondition_satisfied", "relinearization_key_available", "is_warmup"} {
			if !absent(r[k]) {
				if _, ok := boolean(r[k]); !ok {
					add("error", i, k, "expected JSON boolean or not_measured")
				}
			}
		}
		if _, ok := boolean(r["is_warmup"]); !ok {
			add("error", i, "is_warmup", "warmup classification must be explicit boolean")
		}
		w, wok := boolean(r["wrong_output"])
		if x, exists := r["independent_input"]; exists && !absent(x) {
			b, ok := boolean(x)
			if !ok {
				add("error", i, "independent_input", "expected boolean or not_measured")
			} else if b {
				digest := text(r["input_digest_sha256"])
				if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) || r["sample_mode"] != "independent" {
					add("error", i, "independent_input", "independent-input declaration requires sample_mode=independent and a plaintext SHA256 digest")
				}
			}
		}
		a, aok := boolean(r["accepted"])
		s, sok := boolean(r["attack_success"])
		if wok && aok {
			if !sok || s != (w && a) {
				add("error", i, "attack_success", "must equal wrong_output AND accepted when both observations exist")
			}
		} else if !absent(r["attack_success"]) {
			add("error", i, "attack_success", "must remain not_measured if either observation is missing")
		}
		status := text(r["execution_status"])
		validStatus := map[string]bool{"completed": true, "runtime_error": true, "panic": true, "unsupported_configuration": true, "timeout": true, "cancelled": true, "not_started": true}
		if !validStatus[status] {
			add("error", i, "execution_status", "use explicit completed/runtime_error/panic/unsupported_configuration/timeout/cancelled/not_started")
		}
		if status != "completed" {
			if absent(r["error_message"]) || text(r["error_message"]) == "" {
				add("error", i, "error_message", "non-completed execution needs an explicit status reason/original error")
			}
			if sok {
				add("error", i, "attack_success", "non-completed executions must remain not_measured, never an attack failure")
			}
		}
		if status == "completed" && cat == "attack" && (!wok || !aok) {
			add("warning", i, "accepted/wrong_output", "completed trial lacks decisive observations; excluded from success-rate denominator")
		}
		if text(r["verifier"]) == "none" && !absent(r["accepted"]) {
			add("error", i, "accepted", "unauthenticated baseline has no acceptance observation; use not_measured")
		}
		pre := text(r["mathematical_precondition"])
		if pre == "" {
			add("error", i, "mathematical_precondition", "use none, an explicit condition, or not_measured")
		}
		if pre == missing {
			add("warning", i, "mathematical_precondition", "eligibility unverified; not included in conditional denominator")
		} else if pre != "none" {
			if _, ok := boolean(r["precondition_satisfied"]); !ok {
				add("warning", i, "precondition_satisfied", "conditional mathematical eligibility not measured")
			}
		}
		dims, ok := r["input_dimensions"].(map[string]any)
		if !ok || len(dims) == 0 {
			add("warning", i, "input_dimensions", "missing shape; cross-method comparison blocked")
		} else {
			for k, x := range dims {
				n, ok := number(x)
				if !ok || n <= 0 || n != math.Trunc(n) {
					add("error", i, "input_dimensions."+k, "dimensions must be positive integers")
				}
			}
		}
		if absent(r["seed"]) || canonical(r["seed"]) == `""` {
			add("warning", i, "seed", "missing seed or explicit literal/OS-randomness descriptor")
		}
		for k := range r {
			if strings.HasSuffix(k, "_ms") || strings.HasSuffix(k, "_seconds") {
				add("error", i, k, "noncanonical timing unit field; explicitly convert to an _ns field outside this validator")
			}
		}
		if !compatibleBoundary(r["timing_boundary"]) {
			add("warning", i, "timing_boundary", "missing/ambiguous boundary; comparisons blocked; use object with definition and included_stages")
		}
		if absent(r["workload_definition"]) || text(r["workload_definition"]) == "" && canonical(r["workload_definition"]) == `""` {
			add("warning", i, "workload_definition", "missing mathematical definition; comparisons blocked")
		}
		measuredCount := false
		for _, k := range []string{"rotation_count", "ciphertext_multiplication_count", "plaintext_multiplication_count", "addition_count", "key_switch_count"} {
			if !absent(r[k]) {
				measuredCount = true
			}
		}
		src := text(r["operation_count_source"])
		validSource := func(s string) bool { return s == "measured" || s == "analytical" || s == "estimated" }
		if measuredCount && !validSource(src) {
			sources, ok := r["operation_count_source"].(map[string]any)
			if !ok {
				add("error", i, "operation_count_source", "known counts require measured/analytical/estimated, or a per-count source object")
			} else {
				for _, k := range []string{"rotation_count", "ciphertext_multiplication_count", "plaintext_multiplication_count", "addition_count", "key_switch_count"} {
					if !absent(r[k]) && !validSource(text(sources[k])) {
						add("error", i, "operation_count_source."+k, "measured count has no valid source classification")
					}
				}
			}
		}
		for _, k := range []string{"available_rotation_keys", "required_rotation_keys"} {
			if absent(r[k]) {
				continue
			}
			arr, ok := r[k].([]any)
			if !ok {
				add("error", i, k, "expected array of integer offsets or not_measured")
				continue
			}
			keys := map[float64]bool{}
			for _, x := range arr {
				n, ok := number(x)
				if !ok || n != math.Trunc(n) {
					add("error", i, k, "rotation offset must be an integer")
				}
				if keys[n] {
					add("warning", i, k, "duplicate key offset in supplied list")
				}
				keys[n] = true
			}
		}
		if strings.Contains(strings.ToLower(text(r["implementation"])), "sketch") {
			p, pok := number(r["sketch_p"])
			rr, rok := number(r["sketch_r"])
			q, qok := number(r["sketch_Q_auth"])
			if !pok || !rok || !qok {
				add("warning", i, "sketch_assumptions", "p=65537, r=10, Q_auth<=2^32 not fully supplied; authentication assumptions unverified")
			} else if p != 65537 || rr != 10 || q < 1 || q > 4294967296 {
				add("error", i, "sketch_assumptions", "this reporting protocol requires p=65537, r=10, 1<=Q_auth<=2^32")
			}
		}
		if !absent(r["he_security_verified_bits"]) {
			if absent(r["estimator_evidence"]) || text(r["estimator_evidence"]) == "" {
				add("error", i, "he_security_verified_bits", "verified security claim requires supplied estimator evidence; target is not verification")
			}
		}
		if q, ok := number(r["input_reuse_programs"]); ok {
			if q != 1 && q != 2 && q != 4 && q != 8 {
				add("error", i, "input_reuse_programs", "reuse reporting supports 1,2,4,8 programs")
			}
			if absent(r["program_family_id"]) || absent(r["reuse_policy"]) {
				add("warning", i, "reuse_metadata", "missing reuse policy or common program-family identity; reuse comparison blocked")
			}
		}
		parts[GroupKey(r)] = true
	}
	v.Partitions = len(parts)
	if len(parts) > 1 {
		add("info", -1, "partitions", fmt.Sprintf("%d distinct run/workload/profile/boundary groups are kept separate", len(parts)))
	}
	return v
}
func compatibleBoundary(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	desc := strings.TrimSpace(text(m["definition"]))
	arr, ok := m["included_stages"].([]any)
	if len(desc) < 8 || !ok || len(arr) == 0 {
		return false
	}
	for _, x := range arr {
		if strings.TrimSpace(text(x)) == "" || absent(x) {
			return false
		}
	}
	return true
}
func compatibleWorkload(v any) bool {
	if s, ok := v.(string); ok {
		return len(strings.TrimSpace(s)) >= 3 && s != missing && s != "unknown"
	}
	if m, ok := v.(map[string]any); ok {
		return len(strings.TrimSpace(text(m["expression"]))) >= 3
	}
	return false
}
func signature(r Record, keys []string) string {
	m := Record{}
	for _, k := range keys {
		m[k] = r[k]
	}
	return canonical(m)
}

var groupFields = strings.Fields("experiment_id run_id data_origin machine_id metadata_id experiment_category workload workload_definition implementation verifier input_dimensions parameter_profile evaluation_key_profile mathematical_precondition timing_boundary time_unit input_reuse_programs reuse_policy program_family_id sketch_p sketch_r sketch_Q_auth sample_mode")

func GroupKey(r Record) string {
	key := signature(r, groupFields)
	if _, ok := comparisonKey(r, false); !ok {
		key += "|unverified-trial=" + canonical([]any{r["experiment_id"], r["run_id"], r["trial_id"]})
	}
	return key
}
func comparisonKey(r Record, reuse bool) (string, bool) {
	for _, k := range []string{"machine_id", "metadata_id", "parameter_profile", "evaluation_key_profile", "workload", "workload_definition", "input_dimensions"} {
		if absent(r[k]) || text(r[k]) == "" && canonical(r[k]) == `""` {
			return "", false
		}
	}
	if dims, ok := r["input_dimensions"].(map[string]any); !ok || len(dims) == 0 {
		return "", false
	}
	if !compatibleWorkload(r["workload_definition"]) {
		return "", false
	}
	if !compatibleBoundary(r["timing_boundary"]) {
		return "", false
	}
	ks := []string{}
	for _, k := range groupFields {
		if k == "implementation" || k == "verifier" || k == "sketch_p" || k == "sketch_r" || k == "sketch_Q_auth" {
			continue
		}
		if reuse && (k == "input_reuse_programs" || k == "reuse_policy") {
			continue
		}
		ks = append(ks, k)
	}
	if reuse && (absent(r["program_family_id"]) || absent(r["reuse_policy"])) {
		return "", false
	}
	sort.Strings(ks)
	return signature(r, ks), true
}
