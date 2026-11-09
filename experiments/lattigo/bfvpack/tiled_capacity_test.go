package bfvpack

import (
	"testing"

	"dsfgo/matrix"
)

// Capacity-aware tiling must compute the same product as plaintext and use
// fewer tiles than straightforward tiling when checksum rows would otherwise
// spill into an extra block row. This distinguishes required checksum overhead
// (2 extra rows) from avoidable padding overhead (a whole extra block row).
func TestCapacityTilingMatmul(t *testing.T) {
	ctx := NewContext()
	f := ctx.Field()
	// DataSeal-128 shape: 128 data rows + 2 checksum rows = 130 logical rows.
	dataRows, total, d, ell, colTile := 128, 130, 128, 128, 64
	a := randMat(f, total, d, 11)
	b := randMat(f, d, ell, 22)
	want := matrix.Mul(f, a, b)

	if !ctx.CapacityTilingFits(total, dataRows, colTile) {
		t.Fatal("capacity layout should fit for 130x128 at colTile=64")
	}
	ca := ctx.KeyGen(Capability{Rotations: TiledMatmulRotations(d, ell, colTile)})
	eca := ca.EncryptTiledCapacity(a, dataRows, colTile)
	// rotations for capacity layout come from its own column blocking:
	ca2 := ctx.KeyGen(Capability{Rotations: eca.MatmulRotations(ell)})
	eca = ca2.EncryptTiledCapacity(a, dataRows, colTile)
	outCA := ca2.PublicRightMatmulTiled(eca, b, ell)
	gotCA := ca2.DecryptTiled(outCA)
	if !gotCA.Equal(want) {
		t.Fatal("capacity-aware tiled matmul mismatch")
	}

	// straightforward tiling of the same 130-row operand:
	sf := ctx.KeyGen(Capability{Rotations: TiledMatmulRotations(d, ell, colTile)})
	esf := sf.EncryptTiled(a, colTile)
	outSF := sf.PublicRightMatmulTiled(esf, b, ell)
	if !sf.DecryptTiled(outSF).Equal(want) {
		t.Fatal("straightforward tiled matmul mismatch")
	}

	// tile-count comparison: straightforward uses 3 block rows, capacity 2.
	if esf.IBlocks != 3 {
		t.Fatalf("straightforward expected 3 block rows, got %d", esf.IBlocks)
	}
	if eca.IBlocks != 2 {
		t.Fatalf("capacity-aware expected 2 block rows, got %d", eca.IBlocks)
	}
	t.Logf("input tiles straightforward=%d capacity=%d (dim %d)", esf.NumTiles(), eca.NumTiles(), eca.Dim)
}
