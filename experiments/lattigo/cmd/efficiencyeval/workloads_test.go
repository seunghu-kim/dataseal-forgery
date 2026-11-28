package main

import (
	"testing"

	"dsfgo/bfvpack"
	"dsfgo/field"
	"dsfgo/matrix"
	"dsfgo/sketch"
)

func runWorkload(t *testing.T, workload, method, packing string, n, k int) bRecord {
	t.Helper()
	freq, err := clockFrequency()
	if err != nil {
		t.Skip(err)
	}
	c := config{id: "test", seed: 1, peT: tpe, workload: workload, programs: k, trials: 1}
	r := baseRecord([]string{"wrong_output", "accepted"}, c, bRecord{"machine_id": "m", "metadata_id": "x"}, method, packing, n, 0, false)
	g := runTrial(r, c, freq, method, packing, n)
	if !g.Passed {
		t.Fatalf("%s %s %s n=%d k=%d: %v", workload, method, packing, n, k, g.Problems)
	}
	return r
}

// Every workload and method at the smallest size: completed or
// expected-unsupported, correct, accepted, valid timing.
func TestWorkloadsInProcess(t *testing.T) {
	methods := []string{"bfv_only", "dataseal_original", "dataseal_strengthened", "private_sketch", "veritas_rep", "veritas_pe"}
	for _, op := range []string{"element-add", "element-square"} {
		for _, m := range methods {
			r := runWorkload(t, op, m, "elementwise_common", 16, 1)
			t.Logf("%s %s: %v accepted=%v", op, m, r["execution_status"], r["accepted"])
		}
	}
	for _, m := range methods {
		for _, p := range []string{"controlled", "native"} {
			if veritasMethods[m] && p == "controlled" {
				continue
			}
			r := runWorkload(t, "reuse", m, p, 8, 2)
			if r["execution_status"] != "completed" || r["programs_per_trial"] != 2 {
				t.Fatalf("reuse %s %s: %v", m, p, r["execution_status"])
			}
		}
	}
	for _, m := range methods {
		r := runWorkload(t, "compose", m, "native", 4, 1)
		t.Logf("compose %s: %v", m, r["execution_status"])
		if (m == "bfv_only" || m == "private_sketch") != (r["execution_status"] == "completed") {
			t.Fatalf("compose %s status %v", m, r["execution_status"])
		}
	}
}

// Tampering with the intermediate A*B1+D is rejected by the modified scheme; BFV
// only returns a wrong result silently.
func TestComposeIntermediateTamper(t *testing.T) {
	n := 4
	f := field.New(65537)
	a, b1, d, b2 := rnd(f, n, n, 1), rnd(f, n, n, 2), rnd(f, n, n, 3), rnd(f, n, n, 4)
	want := matrix.Mul(f, matrix.Add(f, matrix.Mul(f, a, b1), d), b2)
	ctx := bfvpack.NewContext()
	keys := ctx.KeyGen(bfvpack.Capability{Rotations: bfvpack.PublicMatmulRotations(n, n)})
	layout := bfvpack.MakeLayout(n, n, n, n)
	p1, p2 := keys.PrepareMatmul(layout, b1, n), keys.PrepareMatmul(layout, b2, n)
	ea, ed := keys.Encrypt(a, layout), keys.Encrypt(d, layout)
	cs := sketch.Keygen(f, sketch.RowsFor(65537, 128, 1<<32), n)
	sv := sketch.NewServer()
	sketch.Register(f, &cs, &sv, "A", a)
	sketch.Register(f, &cs, &sv, "D", d)
	target := sketch.Prepare(f, cs, sketch.Program{{Kind: sketch.Input, Label: "A"}, {Kind: sketch.MulRight, Mat: b1}, {Kind: sketch.AddInput, Label: "D"}, {Kind: sketch.MulRight, Mat: b2}})

	honest := keys.Decrypt(composeServer(nil, keys, ea, ed, p1, p2, nil))
	if !honest.Equal(want) || !sketch.Verify(f, cs, target, honest) {
		t.Fatalf("honest composition not correct/accepted")
	}
	delta := matrix.New(n, n)
	delta.Set(1, 2, 5)
	tampered := keys.Decrypt(composeServer(nil, keys, ea, ed, p1, p2, func(c bfvpack.Cipher) bfvpack.Cipher {
		return keys.Add(c, keys.Encrypt(delta, layout)) // server adds Enc(delta) with the public key
	}))
	if tampered.Equal(want) {
		t.Fatalf("tamper had no effect")
	}
	if sketch.Verify(f, cs, target, tampered) {
		t.Fatalf("sketch accepted a tampered intermediate")
	}
	t.Logf("intermediate tamper: output wrong (BFV-only has no check), sketch rejected")
}
