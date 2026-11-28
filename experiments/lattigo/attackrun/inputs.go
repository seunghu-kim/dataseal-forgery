package attackrun

import (
	"crypto/sha256"
	"dsfgo/field"
	"dsfgo/matrix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type inputs struct {
	A, B       matrix.Mat
	K, Eta     []uint64
	Provenance Record
	Digest     string
}

// seededMatrix uses SHA-256 counter blocks with domain separation; rejection
// sampling avoids modulo bias in F_p.
func seededMatrix(f field.Field, r, c int, seed uint64, domain string) matrix.Mat {
	m := matrix.New(r, c)
	counter := uint64(0)
	limit := ^uint64(0) - (^uint64(0) % f.P())
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			for {
				var b [16]byte
				binary.LittleEndian.PutUint64(b[:8], seed)
				binary.LittleEndian.PutUint64(b[8:], counter)
				counter++
				payload := append([]byte(domain+"\x00"), b[:]...)
				h := sha256.Sum256(payload)
				x := binary.LittleEndian.Uint64(h[:8])
				if x < limit {
					m.Set(i, j, x%f.P())
					break
				}
			}
		}
	}
	return m
}
func rows(m matrix.Mat) [][]uint64 {
	out := make([][]uint64, m.Rows())
	for i := range out {
		out[i] = m.Row(i)
	}
	return out
}
func makeInputs(f field.Field, mode, scenario string, s Size, seed uint64) (inputs, error) {
	var x inputs
	x.Provenance = Record{"sample_mode": mode, "he_keygen_encryption_randomness": "library OS randomness; seed not recorded"}
	if mode == "fixed" {
		x.A = matrix.FromInts(f, [][]int64{{1, 0}, {2, 1}, {0, 1}})
		x.B = matrix.FromInts(f, [][]int64{{1, 2}, {3, 4}})
		x.K = []uint64{2, 3, 5}
		x.Eta = []uint64{7, 11}
		if scenario == "addition_kernel" {
			x.B = matrix.FromInts(f, [][]int64{{4, 1}, {0, 9}, {2, 2}})
		}
		if scenario == "square_permute" || scenario == "square_rescale" {
			x.A = matrix.FromInts(f, [][]int64{{2, 3}, {4, 5}, {6, 7}})
		}
		x.Provenance["input_seed"] = "fixed literal fixture; no input seed"
		x.Provenance["source"] = "experiments/lattigo/attacks/attacks_test.go"
	} else if mode == "independent" {
		domain := fmt.Sprintf("ExperimentA/%s/%d:%d:%d:%d", scenario, s.N, s.D, s.Ell, s.Dim)
		x.A = seededMatrix(f, s.N, s.D, seed, domain+"/A")
		br, bc := s.D, s.Ell
		if scenario == "addition_kernel" {
			br, bc = s.N, s.D
		}
		x.B = seededMatrix(f, br, bc, seed, domain+"/B")
		x.K = seededMatrix(f, s.N, 1, seed, domain+"/K").Col(0)
		x.Eta = seededMatrix(f, s.D, 1, seed, domain+"/eta").Col(0)
		x.Provenance["root_input_seed_uint64_decimal"] = fmt.Sprint(seed)
		x.Provenance["generator"] = "SHA256 domain-separated counter with F_p rejection sampling v1"
		x.Provenance["domain"] = domain
		x.Provenance["roles"] = []string{"A", "B", "K", "eta"}
	} else {
		return x, fmt.Errorf("unknown input mode")
	}
	data := Record{"A": rows(x.A)}
	if scenario == "square_permute" || scenario == "square_rescale" {
		data["eta"] = x.Eta
	} else {
		data["B"] = rows(x.B)
		data["checksum_key_K"] = x.K
	}
	b, e := json.Marshal(data)
	if e != nil {
		return x, e
	}
	h := sha256.Sum256(b)
	x.Provenance["fixture_including_authentication_state_sha256"] = hex.EncodeToString(h[:])
	delete(data, "checksum_key_K")
	delete(data, "eta")
	b, e = json.Marshal(data)
	if e != nil {
		return x, e
	}
	h = sha256.Sum256(b)
	x.Digest = hex.EncodeToString(h[:])
	x.Provenance["plaintext_input_sha256"] = x.Digest
	return x, nil
}
