package bfvpack

import "sort"

// OperationTotals counts wrapper operations, not low-level key switches.
type OperationTotals struct {
	Rotate, MulCt, MulPt, Add, Sub, Relin int
}

// OperationMeter is optional, single-threaded instrumentation.
type OperationMeter struct {
	Attempted, Completed                   OperationTotals
	AttemptedRotations, CompletedRotations []int
}

// AvailableEvaluationKeys reports the key material actually present, not the
// requested capability.
func (k Keys) AvailableEvaluationKeys() Capability {
	out := Capability{Relin: k.ek.Rlk != nil, Rotations: []int{}}
	if k.ek.Rtks != nil {
		seen := map[int]bool{}
		for _, offset := range k.Rots {
			if offset == 0 || seen[offset] {
				continue
			}
			if key, ok := k.ek.Rtks.GetRotationKey(k.ctx.Params.GaloisElementForColumnRotationBy(offset)); ok && key != nil {
				out.Rotations = append(out.Rotations, offset)
				seen[offset] = true
			}
		}
	}
	sort.Ints(out.Rotations)
	return out
}

func (m *OperationMeter) begin(op string, offset int) {
	if m == nil {
		return
	}
	switch op {
	case "rotate":
		m.Attempted.Rotate++
		m.AttemptedRotations = append(m.AttemptedRotations, offset)
	case "mul_ct":
		m.Attempted.MulCt++
	case "mul_pt":
		m.Attempted.MulPt++
	case "add":
		m.Attempted.Add++
	case "sub":
		m.Attempted.Sub++
	case "relin":
		m.Attempted.Relin++
	}
}
func (m *OperationMeter) finish(op string, offset int) {
	if m == nil {
		return
	}
	switch op {
	case "rotate":
		m.Completed.Rotate++
		m.CompletedRotations = append(m.CompletedRotations, offset)
	case "mul_ct":
		m.Completed.MulCt++
	case "mul_pt":
		m.Completed.MulPt++
	case "add":
		m.Completed.Add++
	case "sub":
		m.Completed.Sub++
	case "relin":
		m.Completed.Relin++
	}
}
