package bfvpack

import (
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"

	"dsfgo/field"
	"dsfgo/matrix"
)

func pn15() bfv.ParametersLiteral { return bfv.PN15QP880 }

func randMat(f field.Field, r, c int, seed uint64) matrix.Mat {
	m := matrix.New(r, c)
	s := seed*2862933555777941757 + 3037000493
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			s = s*6364136223846793005 + 1442695040888963407
			m.Set(i, j, (s>>11)%f.P())
		}
	}
	return m
}

// Tiled matmul agrees with plaintext matmul, including non-multiple and rectangular sizes.
func TestTiledMatmulCorrect(t *testing.T) {
	ctx := NewContext()
	f := ctx.Field()
	cases := []struct{ n, d, ell, tile int }{
		{8, 8, 8, 4},        // exact multiples, forces 2x2x2 tiling
		{130, 128, 128, 64}, // DataSeal-128 shape (130 rows incl checksum)
		{128, 128, 128, 64}, // bfv_only-128
		{70, 100, 50, 64},   // non-multiples, rectangular
		{5, 5, 5, 64},       // single tile fallback
	}
	for _, tc := range cases {
		a := randMat(f, tc.n, tc.d, 11)
		b := randMat(f, tc.d, tc.ell, 22)
		want := matrix.Mul(f, a, b)
		rots := TiledMatmulRotations(tc.d, tc.ell, tc.tile)
		k := ctx.KeyGen(Capability{Rotations: rots})
		l := NewTiledLayout(tc.n, tc.d, tc.n, tc.tile, tc.tile, false)
		prep := ctx.PrepareTiledMatmul(l, b, tc.ell)
		ec := k.ServerTiledMatmul(k.EncryptTiledLayout(a, l), prep)
		got := k.DecryptTiled(ec)
		if !got.Equal(want) {
			t.Fatalf("tiled matmul mismatch for %+v", tc)
		}
	}
}

// A 128x128 product also fits one PN15 ciphertext; the layout fills the whole half.
func TestSingleCtPN15_128(t *testing.T) {
	if testing.Short() {
		t.Skip("PN15 128x128 is slow")
	}
	ctx := NewContextWith(pn15())
	f := ctx.Field()
	n := 128
	a := randMat(f, n, n, 7)
	b := randMat(f, n, n, 9)
	want := matrix.Mul(f, a, b)
	rots := PublicMatmulRotations(n, n)
	k := ctx.KeyGen(Capability{Rotations: rots})
	ea := k.Encrypt(a, MakeLayout(n, n, n, n))
	ec := k.PublicRightMatmul(ea, b, n)
	got := k.Decrypt(ec)
	if !got.Equal(want) {
		t.Fatal("single-ct PN15 128x128 mismatch")
	}
}
