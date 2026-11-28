package main

import (
	"fmt"
	"runtime"
)

// Every trial records all nine stages, measured or not_applicable.
var stageNames = []string{
	"context_setup",              // S1
	"session_key_generation",     // S2
	"authentication_preparation", // S3
	"public_program_preparation", // S4
	"input_encode_encrypt",       // S5
	"server_evaluation",          // S6
	"verifier_precomputation",    // S7
	"decryption",                 // S8
	"verification_decode",        // S9
}

const boundaryVersion = "B-fair-v3"

type stageObs struct {
	Name   string
	Status string // measured | incomplete | not_applicable
	Begin  int64
	End    int64
	Reason string
}

type subObs struct {
	Ticks int64
	Calls int
}

// stageTimer records raw ticks per stage; sub-stage hooks accumulate across tiles.
type stageTimer struct {
	now      func() int64
	stages   []stageObs
	sub      map[string]*subObs
	subOrder []string
	current  string
	memstats bool
	mem      []bRecord
}

func newStageTimer(now func() int64, memstats bool) *stageTimer {
	return &stageTimer{now: now, sub: map[string]*subObs{}, memstats: memstats}
}

func (t *stageTimer) stage(name string, fn func()) {
	t.current = name
	b := t.now()
	done := false
	defer func() {
		e := t.now()
		st := "measured"
		if !done {
			st = "incomplete"
		}
		t.stages = append(t.stages, stageObs{Name: name, Status: st, Begin: b, End: e})
		if t.memstats {
			// Diagnostic only: stop-the-world read inside the timeline (counted in gaps).
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			t.mem = append(t.mem, bRecord{"after_stage": name, "heap_alloc": ms.HeapAlloc, "heap_inuse": ms.HeapInuse, "heap_sys": ms.HeapSys, "sys": ms.Sys, "num_gc": ms.NumGC})
		}
	}()
	fn()
	done = true
}

func (t *stageTimer) skip(name, reason string) {
	t.stages = append(t.stages, stageObs{Name: name, Status: "not_applicable", Reason: reason})
}

// hook is a veritas.StageHook-compatible sub-stage timer.
func (t *stageTimer) hook(name string, fn func()) {
	key := t.current + "." + name
	b := t.now()
	fn()
	e := t.now()
	s, ok := t.sub[key]
	if !ok {
		s = &subObs{}
		t.sub[key] = s
		t.subOrder = append(t.subOrder, key)
	}
	s.Ticks += e - b
	s.Calls++
}

// ticksToNs converts with integer quotient/remainder (no float rounding).
func ticksToNs(d, freq int64) int64 {
	return d/freq*1000000000 + (d%freq)*1000000000/freq
}

// summarize computes the timing aggregates and the gate problems (none when
// timing is valid).
func summarize(stages []stageObs, freq int64) (bRecord, []string) {
	var problems []string
	if len(stages) != len(stageNames) {
		problems = append(problems, fmt.Sprintf("expected %d stages, got %d", len(stageNames), len(stages)))
	}
	byName := map[string]stageObs{}
	for i, s := range stages {
		if i < len(stageNames) && s.Name != stageNames[i] {
			problems = append(problems, fmt.Sprintf("stage %d is %s, expected %s", i+1, s.Name, stageNames[i]))
		}
		byName[s.Name] = s
	}
	list := []bRecord{}
	var t0, tEnd, prevEnd, sum int64
	first := true
	for _, s := range stages {
		rec := bRecord{"name": s.Name, "status": s.Status}
		switch s.Status {
		case "not_applicable":
			rec["reason"] = s.Reason
		case "measured":
			d := s.End - s.Begin
			rec["begin_ticks"], rec["end_ticks"], rec["duration_ticks"], rec["duration_ns"] = s.Begin, s.End, d, ticksToNs(d, freq)
			if d <= 0 {
				problems = append(problems, fmt.Sprintf("%s duration %d ticks is not positive", s.Name, d))
			}
			if first {
				t0, first = s.Begin, false
			} else if s.Begin < prevEnd {
				problems = append(problems, fmt.Sprintf("%s begins before the previous stage ended", s.Name))
			}
			prevEnd, tEnd = s.End, s.End
			sum += d
		default:
			problems = append(problems, fmt.Sprintf("%s status %s", s.Name, s.Status))
		}
		list = append(list, rec)
	}
	for _, req := range []string{"context_setup", "session_key_generation", "server_evaluation"} {
		if byName[req].Status != "measured" {
			problems = append(problems, req+" not measured")
		}
	}
	out := bRecord{"stages": list, "qpc_frequency_hz": freq}
	if len(problems) > 0 || first {
		return out, append(problems, "aggregates not computed")
	}
	e2e := tEnd - t0
	gap := e2e - sum
	if gap < 0 {
		problems = append(problems, "negative gap")
	}
	srv := byName["server_evaluation"]
	client := (srv.Begin - t0) + (tEnd - srv.End)
	fromKeygen := tEnd - byName["session_key_generation"].Begin
	stageNs := int64(0)
	for _, s := range stages {
		if s.Status == "measured" {
			stageNs += ticksToNs(s.End-s.Begin, freq)
		}
	}
	exact := ticksToNs(e2e, freq) == stageNs+ticksToNs(gap, freq)
	if 1000000000%freq == 0 && !exact {
		problems = append(problems, "sum identity failed in ns")
	}
	out["t0_ticks"], out["t_end_ticks"] = t0, tEnd
	out["e2e_ticks"], out["stage_sum_ticks"], out["gap_ticks"] = e2e, sum, gap
	out["fair_e2e_ns"] = ticksToNs(e2e, freq)
	out["fair_server_ns"] = ticksToNs(srv.End-srv.Begin, freq)
	out["fair_client_ns"] = ticksToNs(client, freq)
	out["fair_gap_ns"] = ticksToNs(gap, freq)
	out["fair_stage_sum_ns"] = stageNs
	out["e2e_from_keygen_ns"] = ticksToNs(fromKeygen, freq)
	out["sum_identity_exact_ns"] = exact
	// Cost split over measured stages: setup + prep + client_online + server + gap = E2E.
	group := func(names ...string) int64 {
		var d int64
		for _, name := range names {
			if s := byName[name]; s.Status == "measured" {
				d += s.End - s.Begin
			}
		}
		return ticksToNs(d, freq)
	}
	out["setup_ns"] = group("context_setup", "session_key_generation", "authentication_preparation")
	out["prep_ns"] = group("public_program_preparation")
	out["client_online_ns"] = group("input_encode_encrypt", "verifier_precomputation", "decryption", "verification_decode")
	out["server_ns"] = group("server_evaluation")
	return out, problems
}

func (t *stageTimer) subRecord(freq int64) bRecord {
	out := bRecord{}
	for _, k := range t.subOrder {
		s := t.sub[k]
		out[k] = bRecord{"ticks": s.Ticks, "duration_ns": ticksToNs(s.Ticks, freq), "calls": s.Calls}
	}
	return out
}
