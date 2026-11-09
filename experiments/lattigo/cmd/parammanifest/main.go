// Command parammanifest emits the ACTUAL pinned-Lattigo BFV parameters (prime
// moduli, bit sizes, ring degree, plaintext modulus, error sigma) as a manifest
// for the lattice-estimator. These are source-derived facts read from the
// pinned module at runtime, not hand-copied constants. It also computes the
// private-sketch authentication rows r by exact integer comparison. It does NOT
// estimate lattice bit-security (that requires the Sage estimator; see
// results/security/estimate_security.sage).
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/ldsec/lattigo/v2/bfv"
)

type paramManifest struct {
	Name         string   `json:"name"`
	LogN         int      `json:"logN"`
	N            int      `json:"N"`
	T            uint64   `json:"plaintext_modulus_t"`
	QPrimes      []uint64 `json:"Q_primes"`
	PPrimes      []uint64 `json:"P_primes"`
	QPrimeBits   []int    `json:"Q_prime_bits"`
	PPrimeBits   []int    `json:"P_prime_bits"`
	Log2Q        int      `json:"log2_Q_bitlen"`
	Log2P        int      `json:"log2_P_bitlen"`
	Log2QP       int      `json:"log2_QP_bitlen"`
	LattigoLogQP int      `json:"lattigo_LogQP"`
	Sigma        float64  `json:"error_sigma"`
	SecretDist   string   `json:"secret_key_distribution"`
	NoteNaming   string   `json:"naming_note"`
}

func manifestFor(name string, lit bfv.ParametersLiteral) paramManifest {
	p, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		panic(err)
	}
	qb := func(xs []uint64) []int {
		o := make([]int, len(xs))
		for i, x := range xs {
			o[i] = new(big.Int).SetUint64(x).BitLen()
		}
		return o
	}
	pprod := big.NewInt(1)
	for _, x := range p.P() {
		pprod.Mul(pprod, new(big.Int).SetUint64(x))
	}
	return paramManifest{
		Name: name, LogN: lit.LogN, N: p.N(), T: p.T(),
		QPrimes: p.Q(), PPrimes: p.P(),
		QPrimeBits: qb(p.Q()), PPrimeBits: qb(p.P()),
		Log2Q:        p.QBigInt().BitLen(),
		Log2P:        pprod.BitLen(),
		Log2QP:       p.QBigInt().BitLen() + pprod.BitLen(),
		LattigoLogQP: p.LogQP(),
		Sigma:        p.Sigma(),
		// Lattigo default GenSecretKey draws a uniform ternary secret in {-1,0,1}
		// per coefficient (full entropy, not sparse). The estimator must use this
		// distribution; do not assume a sparse/hamming-weight secret.
		SecretDist: "uniform_ternary_{-1,0,1}_Lattigo_default_GenSecretKey",
		NoteNaming: "Name encodes log2(QP) (e.g. PN14QP438 => log2(QP)~438), NOT log2(Q). See log2_Q_bitlen vs log2_QP_bitlen.",
	}
}

// authRows returns the smallest r with p^r >= Q_auth * 2^lambda (exact integers).
func authRows(p uint64, lambda uint, qAuthLog2 uint) (r int, lhsBits, rhsBits int) {
	rhs := new(big.Int).Lsh(big.NewInt(1), qAuthLog2+lambda) // Q_auth * 2^lambda = 2^(qAuthLog2+lambda)
	pb := new(big.Int).SetUint64(p)
	acc := big.NewInt(1)
	for r = 0; r < 100; r++ {
		if acc.Cmp(rhs) >= 0 {
			return r, acc.BitLen(), rhs.BitLen()
		}
		acc.Mul(acc, pb)
	}
	return -1, 0, rhs.BitLen()
}

func main() {
	out := "../../results/security/param_manifest.json"
	if len(os.Args) == 2 {
		out = os.Args[1]
	}
	os.MkdirAll(dir(out), 0o755)

	ms := []paramManifest{
		manifestFor("PN13QP218", bfv.PN13QP218),
		manifestFor("PN14QP438", bfv.PN14QP438),
		manifestFor("PN15QP880", bfv.PN15QP880),
	}

	// authentication rows: p=65537, lambda=128, Q_auth=2^32
	r10, lhsBits, rhsBits := authRows(65537, 128, 32)

	manifest := map[string]interface{}{
		"source":     "github.com/ldsec/lattigo/v2 pinned v2.2.1-0.20210923173451-d9eb44f2c43f (replace in go.mod)",
		"derivation": "read at runtime from bfv.NewParametersFromLiteral; primes/bitlengths are source-derived facts, not hand-copied",
		"params":     ms,
		"authentication": map[string]interface{}{
			"p":                65537,
			"lambda_auth":      128,
			"Q_auth":           "2^32",
			"rule":             "smallest r with p^r >= Q_auth * 2^lambda, exact integer comparison",
			"r":                r10,
			"p_r_bitlen":       lhsBits,
			"threshold_bitlen": rhsBits,
			"note":             "authentication soundness only; independent from FHE lattice bit-security; assumes no verification-oracle feedback",
		},
		"he_security_bits": "UNVERIFIED — requires running results/security/estimate_security.sage with Sage; NOT asserted here",
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(out, b, 0o644)
	fmt.Printf("wrote %s\n", out)
	for _, m := range ms {
		fmt.Printf("%-10s N=%d log2Q=%d log2P=%d log2QP=%d (lattigo LogQP=%d) sigma=%.4f t=%d\n",
			m.Name, m.N, m.Log2Q, m.Log2P, m.Log2QP, m.LattigoLogQP, m.Sigma, m.T)
	}
	fmt.Printf("auth rows r=%d (p^r bitlen=%d >= threshold bitlen=%d)\n", r10, lhsBits, rhsBits)
}

func dir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
