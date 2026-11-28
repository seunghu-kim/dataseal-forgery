package main

import (
	"math"
	"strings"
	"testing"

	"dsfgo/bfvpack"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
)

func sketchArgs(extra ...string) []string {
	return append([]string{"--repo", ".", "--out", "x", "--metadata", "m.json", "--run-id", "t", "--pe-t", "18014398507614209"}, extra...)
}

// --sketch-rows: default 0 (RowsFor path); override only for matmul private_sketch.
func TestSketchRowsFlag(t *testing.T) {
	c, err := parseConfig(sketchArgs())
	if err != nil || c.sketchRows != 0 || sketchRowsUsed(c.sketchRows) != 10 {
		t.Fatalf("default: rows=%d used=%d err=%v", c.sketchRows, sketchRowsUsed(c.sketchRows), err)
	}
	if c, err = parseConfig(sketchArgs("--methods", "private_sketch,dataseal_original", "--packings", "controlled", "--sketch-rows", "1")); err != nil || c.sketchRows != 1 {
		t.Fatalf("override rejected: %v", err)
	}
	for _, bad := range [][]string{
		{"--methods", "dataseal_original", "--sketch-rows", "1"},
		{"--methods", "private_sketch", "--workload", "element-add", "--sizes", "16", "--sketch-rows", "1"},
		{"--methods", "private_sketch", "--workload", "compose", "--sketch-rows", "1"},
		{"--methods", "private_sketch", "--sketch-rows", "-1"},
	} {
		if _, err := parseConfig(sketchArgs(bad...)); err == nil {
			t.Fatalf("accepted invalid %v", bad)
		}
	}
}

func TestSketchBoundFields(t *testing.T) {
	d := sketchBoundFields(0)
	if d["sketch_rows"] != 10 || d["security_below_target"] != false || !strings.Contains(d["sketch_rows_source"].(string), "default") {
		t.Fatalf("default bound fields: %v", d)
	}
	if u := d["forgery_bound_union_log2"].(float64); u > -128 || u < -128.01 {
		t.Fatalf("r=10 union log2 %v", u)
	}
	o := sketchBoundFields(1)
	if o["sketch_rows"] != 1 || o["security_below_target"] != true || !strings.Contains(o["sketch_rows_source"].(string), "override") {
		t.Fatalf("override bound fields: %v", o)
	}
	if p := o["forgery_bound_per_attempt_log2"].(float64); math.Abs(p+16) > 0.01 {
		t.Fatalf("r=1 per-attempt log2 %v", p)
	}
	if u := o["forgery_bound_union_log2"].(float64); u < 15.99 || !strings.Contains(o["forgery_bound_union"].(string), "vacuous") {
		t.Fatalf("r=1 union %v %v", u, o["forgery_bound_union"])
	}
	sec := trialSecurity(config{workload: "matmul", sketchRows: 1}, "private_sketch")
	if sec["security_below_target"] != true || !strings.Contains(sec["authentication"].(string), "r=1") {
		t.Fatalf("r=1 security block: %v", sec)
	}
	def := trialSecurity(config{workload: "matmul"}, "private_sketch")
	if def["authentication"] != methodSecurity("private_sketch", 0)["authentication"] || def["security_below_target"] != false {
		t.Fatalf("default security block changed: %v", def)
	}
	if _, ok := trialSecurity(config{workload: "compose"}, "private_sketch")["sketch_rows"]; ok {
		t.Fatalf("non-matmul workloads must keep the original security block")
	}
}

// r=1: the honest product is accepted; a tampered BFV output is rejected.
func TestSketchR1AcceptsHonestRejectsTamper(t *testing.T) {
	n := 8
	f := field.New(65537)
	a, b := rnd(f, n, n, 1), rnd(f, n, n, 2)
	want := matrix.Mul(f, a, b)
	cs := sketch.Keygen(f, 1, n)
	if cs.K.Rows() != 1 || cs.K.Cols() != n {
		t.Fatalf("K shape %dx%d", cs.K.Rows(), cs.K.Cols())
	}
	sv := sketch.NewServer()
	sketch.Register(f, &cs, &sv, "A", a)
	target := sketch.Prepare(f, cs, sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b}})

	ctx := bfvpack.NewContext()
	keys := ctx.KeyGen(bfvpack.Capability{Rotations: bfvpack.PublicMatmulRotations(n, n)})
	layout := bfvpack.MakeLayout(n, n, n, n)
	prep := keys.PrepareMatmul(layout, b, n)
	out := keys.ServerMatmul(keys.Encrypt(a, layout), prep)
	honest := keys.Decrypt(out)
	if !honest.Equal(want) || !sketch.Verify(f, cs, target, honest) {
		t.Fatalf("r=1 honest output not correct/accepted")
	}
	// Server-side tamper: add Enc(delta) with the public key (single entry, delta != 0).
	delta := matrix.New(n, n)
	delta.Set(3, 5, 1234)
	tampered := keys.Decrypt(keys.Add(out, keys.Encrypt(delta, layout)))
	if tampered.Equal(want) {
		t.Fatalf("tamper had no effect")
	}
	if sketch.Verify(f, cs, target, tampered) {
		t.Fatalf("r=1 sketch accepted a tampered output")
	}
	// Plaintext tamper on every entry (i,j) by +1: K*(Y+E_ij) - K*Y = K[0,i]*e_j,
	// so it is rejected exactly when K[0,i] != 0 (K[0,i]=0 has prob 1/p).
	rejected, total := 0, 0
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			e := matrix.New(n, n)
			e.Set(i, j, 1)
			got := !sketch.Verify(f, cs, target, matrix.Add(f, want, e))
			if got != (cs.K.At(0, i) != 0) {
				t.Fatalf("r=1 tamper (%d,%d): rejected=%v, K[0,%d]=%d", i, j, got, i, cs.K.At(0, i))
			}
			total++
			if got {
				rejected++
			}
		}
	}
	t.Logf("r=1: honest accepted, BFV tamper rejected, single-entry tampers rejected %d/%d", rejected, total)
}

// r=1 and the default r=10 are both correct and accepted, and server operation
// counts do not depend on r.
func TestMatmulSketchRowsInProcess(t *testing.T) {
	freq, err := clockFrequency()
	if err != nil {
		t.Skip(err)
	}
	counts := map[int][4]interface{}{}
	for _, rows := range []int{0, 1} {
		c := config{id: "test", seed: 1, peT: tpe, workload: "matmul", programs: 1, trials: 1, sketchRows: rows}
		r := baseRecord([]string{"wrong_output", "accepted"}, c, bRecord{"machine_id": "m", "metadata_id": "x"}, "private_sketch", "controlled", 8, 0, false)
		g := runTrial(r, c, freq, "private_sketch", "controlled", 8)
		if !g.Passed || r["accepted"] != true || r["wrong_output"] != false {
			t.Fatalf("rows=%d: passed=%v accepted=%v wrong=%v %v", rows, g.Passed, r["accepted"], r["wrong_output"], g.Problems)
		}
		want := sketchRowsUsed(rows)
		if r["sketch_r"] != want || r["sketch_K_rows"] != want || r["sketch_rows"] != want {
			t.Fatalf("rows=%d: sketch_r=%v K_rows=%v", rows, r["sketch_r"], r["sketch_K_rows"])
		}
		if r["security_below_target"] != (rows == 1) {
			t.Fatalf("rows=%d: security_below_target=%v", rows, r["security_below_target"])
		}
		counts[rows] = [4]interface{}{r["rotation_count"], r["ciphertext_multiplication_count"], r["plaintext_multiplication_count"], r["addition_count"]}
	}
	if counts[0] != counts[1] {
		t.Fatalf("server operation counts depend on r: r=10 %v, r=1 %v", counts[0], counts[1])
	}
	t.Logf("server counts (rot, mulct, mulpt, add) = %v for r=10 and r=1", counts[0])
}
