// Package attacks implements the ciphertext-level attacks on DataSeal verification,
// using only server-visible data and the provisioned evaluation keys.
package attacks

import (
	"dsfgo/bfvpack"
	"dsfgo/field"
)

// KernelChoice selects the two input columns and the output column of the kernel attack.
type KernelChoice struct{ ColA, ColB, Target int }

// SelectiveScaling is the selective multiplication attack with R = cI: rows 0..n
// are multiplied by c and the golden row n+1 is left unchanged.
func SelectiveScaling(k bfvpack.Keys, f field.Field, evaluated bfvpack.Cipher, n int, factor uint64) bfvpack.Cipher {
	l := evaluated.Layout
	mask := make([]uint64, lenSlots(k))
	for i := 0; i <= n+1; i++ {
		for j := 0; j < l.LogicalCols; j++ {
			if i <= n {
				mask[l.Slot(i, j)] = factor
			} else {
				mask[l.Slot(i, j)] = 1
			}
		}
	}
	return k.MulMask(evaluated, mask)
}

// encryptedKernelColumn builds h_i = w_b*A_{i,a} - w_a*A_{i,b} in the target column.
func encryptedKernelColumn(k bfvpack.Keys, encodedInput bfvpack.Cipher, n int, choice KernelChoice) bfvpack.Cipher {
	a := selectDataColumn(k, encodedInput, n, choice.ColA, choice.Target)
	b := selectDataColumn(k, encodedInput, n, choice.ColB, choice.Target)
	wb := broadcastChecksum(k, encodedInput, n, choice.ColB, choice.Target)
	wa := broadcastChecksum(k, encodedInput, n, choice.ColA, choice.Target)
	p := k.MulCipher(wb, a)
	q := k.MulCipher(wa, b)
	return k.Sub(p, q)
}

// KernelAdjustedOutput is the kernel attack: it adds h (k^T h = 0) to the output
// and leaves the checksum rows unchanged.
func KernelAdjustedOutput(k bfvpack.Keys, encodedInput, evaluated bfvpack.Cipher, n int, choice KernelChoice) bfvpack.Cipher {
	h := encryptedKernelColumn(k, encodedInput, n, choice)
	return k.Add(evaluated, h.WithLayout(evaluated.Layout))
}

func selectDataColumn(k bfvpack.Keys, src bfvpack.Cipher, n, fromCol, toCol int) bfvpack.Cipher {
	l := src.Layout
	mask := make([]uint64, lenSlots(k))
	for i := 0; i < n; i++ {
		mask[l.Slot(i, fromCol)] = 1
	}
	selected := k.MulMask(src, mask)
	return synthRotate(k, selected, fromCol-toCol)
}

func broadcastChecksum(k bfvpack.Keys, src bfvpack.Cipher, n, checksumCol, targetCol int) bfvpack.Cipher {
	l := src.Layout
	mask := make([]uint64, lenSlots(k))
	mask[l.Slot(n, checksumCol)] = 1
	single := k.MulMask(src, mask)
	// Bring checksum row n to row 0, align its column, then replicate down the data rows.
	firstRow := synthRotate(k, single, n*l.Dim)
	aligned := synthRotate(k, firstRow, checksumCol-targetCol)
	out := aligned
	for i := 1; i < n; i++ {
		out = k.Add(out, synthRotate(k, aligned, -i*l.Dim))
	}
	return out
}

// SquarePermute is the permutation attack: it swaps two data rows within one column.
func SquarePermute(k bfvpack.Keys, evaluated bfvpack.Cipher, n, r1, r2, col int) bfvpack.Cipher {
	l := evaluated.Layout
	keep := ones(lenSlots(k))
	sel1 := make([]uint64, lenSlots(k))
	sel2 := make([]uint64, lenSlots(k))
	keep[l.Slot(r1, col)] = 0
	keep[l.Slot(r2, col)] = 0
	sel1[l.Slot(r1, col)] = 1
	sel2[l.Slot(r2, col)] = 1
	rest := k.MulMask(evaluated, keep)
	row1 := k.MulMask(evaluated, sel1)
	row2 := k.MulMask(evaluated, sel2)
	shift := (r1 - r2) * l.Dim
	moved1 := synthRotate(k, row1, shift)
	moved2 := synthRotate(k, row2, -shift)
	return k.Add(k.Add(rest, moved1), moved2)
}

// SquareRescale is the compensating rescaling attack: two entries of one column
// are multiplied by gamma and gamma^-1.
func SquareRescale(k bfvpack.Keys, f field.Field, evaluated bfvpack.Cipher, col, r1, r2 int, gamma uint64) bfvpack.Cipher {
	l := evaluated.Layout
	mask := ones(lenSlots(k))
	mask[l.Slot(r1, col)] = gamma
	mask[l.Slot(r2, col)] = f.Inv(gamma)
	return k.MulMask(evaluated, mask)
}

func lenSlots(k bfvpack.Keys) int { return k.Slots() }

func ones(n int) []uint64 {
	v := make([]uint64, n)
	for i := range v {
		v[i] = 1
	}
	return v
}
