package main

import (
	"math"
	"sort"
)

type Metric struct {
	N      int `json:"n"`
	Median any `json:"median_ns"`
	Q1     any `json:"q1_ns"`
	Q3     any `json:"q3_ns"`
	IQR    any `json:"iqr_ns"`
}
type Rate struct {
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
	Value       any    `json:"rate"`
	Definition  string `json:"definition"`
}
type Summary struct {
	Identity                Record            `json:"identity"`
	Provided                int               `json:"provided_records"`
	Warmups                 int               `json:"warmup_records_excluded"`
	Attempted               int               `json:"attempted_trials"`
	Completed               int               `json:"completed_trials"`
	Eligible                int               `json:"eligible_completed_trials"`
	Decisive                int               `json:"eligible_trials_with_both_observations"`
	AcceptedIncorrect       int               `json:"accepted_incorrect_completed_trials"`
	EligibleSuccess         int               `json:"eligible_accepted_incorrect_trials"`
	Conditional             Rate              `json:"conditional_success"`
	Completion              Rate              `json:"completion"`
	DistinctPlaintextInputs any               `json:"distinct_plaintext_inputs"`
	IndependentInputTrials  any               `json:"distinct_input_trials_declared_independent"`
	IndependentConditional  Rate              `json:"independent_input_conditional_success"`
	Statuses                map[string]int    `json:"execution_status_counts"`
	Metrics                 map[string]Metric `json:"metrics"`
	Target                  any               `json:"performance_repetition_target"`
	TargetStatus            string            `json:"target_status"`
}

func quantile(xs []float64, p float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	h := p * float64(len(s)-1)
	lo := int(math.Floor(h))
	hi := int(math.Ceil(h))
	return s[lo] + (s[hi]-s[lo])*(h-float64(lo))
}
func metric(xs []float64) Metric {
	if len(xs) == 0 {
		return Metric{0, missing, missing, missing, missing}
	}
	q1, q3 := quantile(xs, .25), quantile(xs, .75)
	return Metric{len(xs), quantile(xs, .5), q1, q3, q3 - q1}
}
func rate(n, d int, def string) Rate {
	var v any = missing
	if d > 0 {
		v = float64(n) / float64(d)
	}
	return Rate{n, d, v, def}
}
func eligible(r Record) bool {
	if text(r["mathematical_precondition"]) == "none" {
		return true
	}
	b, ok := boolean(r["precondition_satisfied"])
	return text(r["mathematical_precondition"]) != missing && ok && b
}
func timingEligible(r Record) bool {
	if text(r["execution_status"]) != "completed" || r["is_warmup"] == true || !eligible(r) {
		return false
	}
	if text(r["experiment_category"]) == "performance" {
		w, ok := boolean(r["wrong_output"])
		if !ok || w {
			return false
		}
		if text(r["verifier"]) != "none" {
			a, ok := boolean(r["accepted"])
			if !ok || !a {
				return false
			}
		}
	}
	return true
}
func Analyze(rows []Record) []Summary {
	groups := map[string][]Record{}
	for _, r := range rows {
		groups[GroupKey(r)] = append(groups[GroupKey(r)], r)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []Summary{}
	for _, k := range keys {
		rs := groups[k]
		s := Summary{Identity: Record{}, Provided: len(rs), Statuses: map[string]int{}, Metrics: map[string]Metric{}, Target: missing, TargetStatus: "not_applicable"}
		for _, f := range groupFields {
			v, ok := rs[0][f]
			if !ok {
				v = missing
			}
			s.Identity[f] = v
		}
		if _, ok := comparisonKey(rs[0], false); !ok {
			s.Identity["unverified_partition_trial_id"] = rs[0]["trial_id"]
		}
		samples := map[string][]float64{}
		inputHashes, independentSeen := map[string]bool{}, map[string]bool{}
		hasHashes, hasDeclarations := false, false
		independentAttempts, independentDecisive, independentSuccess := 0, 0, 0
		metrics := append(append([]string{}, timeFields...), "packing_time_ns", "direct_computation_time_ns", "program_preparation_time_ns", "client_preparation_total_ns", "paired_client_preparation_ns", "paired_direct_computation_ns")
		for _, r := range rs {
			if r["is_warmup"] == true {
				s.Warmups++
				continue
			}
			status := text(r["execution_status"])
			digest := text(r["input_digest_sha256"])
			if digest != "" && digest != missing {
				hasHashes = true
				inputHashes[digest] = true
			}
			if declared, ok := boolean(r["independent_input"]); ok {
				hasDeclarations = true
				if declared && digest != "" && digest != missing && !independentSeen[digest] {
					independentSeen[digest] = true
					if status != "not_started" {
						independentAttempts++
					}
					if status == "completed" && eligible(r) {
						w, wok := boolean(r["wrong_output"])
						a, aok := boolean(r["accepted"])
						if wok && aok {
							independentDecisive++
							if w && a {
								independentSuccess++
							}
						}
					}
				}
			}
			s.Statuses[status]++
			if status != "not_started" {
				s.Attempted++
			}
			if status != "completed" {
				continue
			}
			s.Completed++
			w, wok := boolean(r["wrong_output"])
			a, aok := boolean(r["accepted"])
			if wok && aok && w && a {
				s.AcceptedIncorrect++
			}
			if eligible(r) {
				s.Eligible++
				if wok && aok {
					s.Decisive++
					if w && a {
						s.EligibleSuccess++
					}
				}
			}
			if timingEligible(r) {
				for _, m := range metrics {
					if m == "client_preparation_total_ns" {
						p, pok := number(r["preparation_time_ns"])
						e, eok := number(r["encryption_time_ns"])
						if pok && eok {
							samples[m] = append(samples[m], p+e)
						}
					} else if v, ok := number(r[m]); ok {
						samples[m] = append(samples[m], v)
					}
				}
				p, pok := number(r["preparation_time_ns"])
				e, eok := number(r["encryption_time_ns"])
				d, dok := number(r["direct_computation_time_ns"])
				if pok && eok && dok {
					samples["paired_client_preparation_ns"] = append(samples["paired_client_preparation_ns"], p+e)
					samples["paired_direct_computation_ns"] = append(samples["paired_direct_computation_ns"], d)
				}
			}
		}
		s.Conditional = rate(s.EligibleSuccess, s.Decisive, "accepted incorrect / completed non-warmup precondition-eligible trials with both correctness and acceptance measured")
		s.Completion = rate(s.Completed, s.Attempted, "completed / attempted non-warmup trials; not_started excluded from attempts")
		s.DistinctPlaintextInputs = missing
		s.IndependentInputTrials = missing
		if hasHashes {
			s.DistinctPlaintextInputs = len(inputHashes)
		}
		if hasDeclarations {
			s.IndependentInputTrials = independentAttempts
		}
		s.IndependentConditional = rate(independentSuccess, independentDecisive, "first supplied non-warmup observation per plaintext digest explicitly declared independent; completed and precondition eligible, both observations measured; distinct inputs do not prove statistical independence")
		for _, m := range metrics {
			s.Metrics[m] = metric(samples[m])
		}
		if text(rs[0]["experiment_category"]) == "performance" {
			s.TargetStatus = "target_not_defined_for_shape"
			if dims, ok := rs[0]["input_dimensions"].(map[string]any); ok {
				if n, ok := number(dims["n"]); ok {
					target := 0
					if n <= 64 {
						target = 20
					} else if n == 128 {
						target = 10
					}
					if target > 0 {
						s.Target = target
						s.TargetStatus = "unmet"
						if s.Metrics["total_time_ns"].N >= target {
							s.TargetStatus = "met"
						}
					}
				}
			}
		}
		out = append(out, s)
	}
	return out
}
