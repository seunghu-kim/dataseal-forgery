package bfvpack

import (
	"math/big"
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
)

// Guards against silent upstream changes to the pinned BFV parameter sets.
func TestParameterManifestDrift(t *testing.T) {
	cases := []struct {
		lit                 bfv.ParametersLiteral
		name                string
		n                   int
		t                   uint64
		log2Q, log2P, logQP int
	}{
		{bfv.PN13QP218, "PN13QP218", 8192, 65537, 163, 55, 218},
		{bfv.PN14QP438, "PN14QP438", 16384, 65537, 328, 110, 438},
		{bfv.PN15QP880, "PN15QP880", 32768, 65537, 700, 181, 880},
	}
	for _, c := range cases {
		p, err := bfv.NewParametersFromLiteral(c.lit)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if p.N() != c.n || p.T() != c.t {
			t.Fatalf("%s drift: N=%d t=%d", c.name, p.N(), p.T())
		}
		if p.QBigInt().BitLen() != c.log2Q {
			t.Fatalf("%s log2(Q) drift: got %d want %d", c.name, p.QBigInt().BitLen(), c.log2Q)
		}
		pprod := big.NewInt(1)
		for _, x := range p.P() {
			pprod.Mul(pprod, new(big.Int).SetUint64(x))
		}
		if pprod.BitLen() != c.log2P {
			t.Fatalf("%s log2(P) drift: got %d want %d", c.name, pprod.BitLen(), c.log2P)
		}
		if p.LogQP() != c.logQP {
			t.Fatalf("%s LogQP drift: got %d want %d", c.name, p.LogQP(), c.logQP)
		}
		if p.Sigma() != 3.2 {
			t.Fatalf("%s sigma drift: %v", c.name, p.Sigma())
		}
	}
}

// Authentication rows r for the stated configuration, by exact integer rule.
func TestAuthRowsExact(t *testing.T) {
	// smallest r with p^r >= 2^(32+128), p=65537
	rhs := new(big.Int).Lsh(big.NewInt(1), 32+128)
	p := big.NewInt(65537)
	acc := big.NewInt(1)
	r := 0
	for ; acc.Cmp(rhs) < 0; r++ {
		acc.Mul(acc, p)
	}
	if r != 10 {
		t.Fatalf("auth rows: got r=%d want 10", r)
	}
}
