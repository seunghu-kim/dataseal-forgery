package bfvpack

import (
	"dsfgo/matrix"
	"testing"
)

func TestPreparedTiledMatmul(t *testing.T) {
	ctx := NewContext()
	f := ctx.Field()
	for _, tc := range []struct {
		name                             string
		rows, cols, out, data, tile, dim int
		capacity                         bool
	}{
		{"uniform_rectangular", 7, 6, 5, 7, 4, 4, false},
		{"capacity_checksum_rows", 10, 8, 7, 8, 4, 6, true},
		{"controlled_empty_slots", 8, 8, 8, 8, 4, 6, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := NewTiledLayout(tc.rows, tc.cols, tc.data, tc.tile, tc.dim, tc.capacity)
			a, b := randMat(f, tc.rows, tc.cols, 11), randMat(f, tc.cols, tc.out, 22)
			prep := ctx.PrepareTiledMatmul(l, b, tc.out)
			keys := ctx.KeyGen(Capability{Rotations: tiledRotations(l.ColOffsets, uniformOffsets(tc.out, tc.tile))})
			in := keys.EncryptTiledLayout(a, l)
			got := keys.ServerTiledMatmul(in, prep)
			want := matrix.Mul(f, a, b)
			if !keys.DecryptTiled(got).Equal(want) {
				t.Fatal("output mismatch")
			}
			// Program owns its public geometry; mutating the caller's offsets must not
			// corrupt it. Cipher encryption also owns its geometry independently.
			l.RowOffsets[1]++
			keys.ResetCount()
			if !keys.DecryptTiled(keys.ServerTiledMatmul(in, prep)).Equal(want) {
				t.Fatal("aliased geometry")
			}
		})
	}
}

func TestPreparedTiledCapacityRejected(t *testing.T) {
	c := NewContext()
	defer func() {
		if recover() == nil {
			t.Fatal("oversized layout accepted")
		}
	}()
	c.PrepareTiledMatmul(NewTiledLayout(128, 128, 128, 128, 128, false), matrix.New(128, 128), 128)
}
