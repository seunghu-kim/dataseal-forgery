package bfvpack

import "testing"

// These instrumentation tests use no encryption, keys or attack calls.
func TestOperationMeterCompletedAndAttempted(t *testing.T) {
	m := &OperationMeter{}
	for _, op := range []string{"rotate", "mul_ct", "mul_pt", "add", "sub", "relin"} {
		m.begin(op, 7)
		m.finish(op, 7)
	}
	m.begin("rotate", 11)
	if m.Attempted.Rotate != 2 || m.Completed.Rotate != 1 || m.Completed.MulCt != 1 || m.Completed.MulPt != 1 || m.Completed.Add != 1 || m.Completed.Sub != 1 || m.Completed.Relin != 1 {
		t.Fatalf("wrong accounting: %+v", m)
	}
	if len(m.CompletedRotations) != 1 || m.CompletedRotations[0] != 7 || m.AttemptedRotations[1] != 11 {
		t.Fatal("rotation trace mismatch")
	}
	var none *OperationMeter
	none.begin("add", 0)
	none.finish("add", 0)
}
func TestOperationMeterFailureDoesNotCountCompletion(t *testing.T) {
	cases := []struct {
		name      string
		call      func(Keys)
		attempted func(*OperationMeter) int
		completed func(*OperationMeter) int
	}{
		{"rotate", func(k Keys) { k.RotateCols(Cipher{}, 1) }, func(m *OperationMeter) int { return m.Attempted.Rotate }, func(m *OperationMeter) int { return m.Completed.Rotate }},
		{"mul_ct", func(k Keys) { k.MulCipher(Cipher{}, Cipher{}) }, func(m *OperationMeter) int { return m.Attempted.MulCt }, func(m *OperationMeter) int { return m.Completed.MulCt }},
		{"sub", func(k Keys) { k.Sub(Cipher{}, Cipher{}) }, func(m *OperationMeter) int { return m.Attempted.Sub }, func(m *OperationMeter) int { return m.Completed.Sub }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &OperationMeter{}
			k := Keys{Count: &Counts{}, Meter: m}
			var observed interface{}
			func() { defer func() { observed = recover() }(); tc.call(k) }()
			if observed == nil {
				t.Fatal("expected nil-evaluator test failure")
			}
			if tc.attempted(m) != 1 || tc.completed(m) != 0 {
				t.Fatalf("failed operation counted completed: %+v", m)
			}
		})
	}
}
func TestOperationMeterZeroRotationIsNoOperation(t *testing.T) {
	m := &OperationMeter{}
	k := Keys{Count: &Counts{}, Meter: m}
	k.RotateCols(Cipher{}, 0)
	if m.Attempted.Rotate != 0 || m.Completed.Rotate != 0 {
		t.Fatal("zero rotation counted")
	}
}
func TestOperationMeterMaterialCapabilityDoesNotTrustFlags(t *testing.T) {
	k := Keys{Relin: true, Rots: []int{1, -1}}
	actual := k.AvailableEvaluationKeys()
	if actual.Relin || len(actual.Rotations) != 0 {
		t.Fatal("requested flags reported as actual key material")
	}
}
