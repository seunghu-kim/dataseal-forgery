package veritas

import (
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche_1"
	"veritas/vche/vche_2"

	"dsfgo/matrix"
)

func elementSession(t *testing.T, name string, relin bool) Scheme {
	t.Helper()
	if name == "rep" {
		r, err := NewRepParams(bfv.PN14QP438, 64)
		if err != nil {
			t.Fatal(err)
		}
		r.KeyGenRelin(nil, relin, nil)
		return r
	}
	p, err := NewPeParams(litT(TPE))
	if err != nil {
		t.Fatal(err)
	}
	p.KeyGenRelin(nil, relin, nil)
	return p
}

// Elementwise add and square are exact and accepted; only squaring gets a
// relinearisation key.
func TestElementAddSquareCorrect(t *testing.T) {
	for _, name := range []string{"rep", "pe"} {
		for _, op := range []string{"add", "square"} {
			for _, n := range []int{16, 32} {
				s := elementSession(t, name, op == "square")
				a, d := vmat(f17, n, 1, 1), vmat(f17, n, 1, 2)
				ia, id := EncryptVector(s, a.Col(0), nil), ElementInput{}
				if op == "add" {
					id = EncryptVector(s, d.Col(0), nil)
				}
				res := ElementServer(s, op, ia, id)
				ElementVerifier(s, op, ia, id, &res)
				ElementDecrypt(s, &res)
				vals, err := ElementVerify(s, res, n)
				if err != nil {
					t.Fatalf("%s %s n=%d rejected: %v", name, op, n, err)
				}
				want := matrix.Add(f17, a, d)
				if op == "square" {
					want = matrix.Square(f17, a)
				}
				for i := 0; i < n; i++ {
					if vals[i]%65537 != want.At(i, 0) {
						t.Fatalf("%s %s n=%d wrong at %d", name, op, n, i)
					}
				}
			}
		}
	}
}

// Tamper: adding an encrypted delta to the server output is rejected.
func TestElementTamperRejected(t *testing.T) {
	for _, name := range []string{"rep", "pe"} {
		s := elementSession(t, name, true)
		a := vmat(f17, 16, 1, 1)
		ia := EncryptVector(s, a.Col(0), nil)
		res := ElementServer(s, "square", ia, ElementInput{})
		ElementVerifier(s, "square", ia, ElementInput{}, &res)
		switch x := s.(type) {
		case *Rep:
			v := make([]uint64, x.Params.N())
			for j := 0; j < x.Params.NumReplications; j++ {
				v[j] = 3
			}
			c := x.evaluator.CopyNew(res.ct.(*vche_1.Ciphertext)).(*vche_1.Ciphertext)
			bfv.NewEvaluator(x.Params.Parameters, rlwe.EvaluationKey{}).Add(c.Ciphertext, encryptPublicVec(x.Params.Parameters, x.pubEnc, x.pk.PublicKey, v), c.Ciphertext)
			res.ct = c
		case *Pe:
			v := make([]uint64, x.Params.N())
			v[0] = 3
			c := res.ct.(*vche_2.Ciphertext)
			parts := append([]*bfv.Ciphertext(nil), c.Ciphertexts...)
			parts[0] = bfv.NewEvaluator(x.Params.Parameters, rlwe.EvaluationKey{}).AddNew(parts[0], encryptPublicVec(x.Params.Parameters, x.pubEnc, x.pk, v))
			res.ct = &vche_2.Ciphertext{Ciphertexts: parts}
		}
		ElementDecrypt(s, &res)
		if _, err := ElementVerify(s, res, 16); err == nil {
			t.Fatalf("%s: tampered square output accepted", name)
		}
	}
}

// Tag independence: with one encrypted input and two public programs, swapped
// outputs are rejected.
func TestReuseProgramOutputSwapRejected(t *testing.T) {
	cases := []struct {
		name  string
		block int
	}{{"rep", 8}, {"pe", 16}}
	for _, c := range cases {
		g := NewGeometry(16, 16, 16, c.block)
		var s Scheme
		if c.name == "rep" {
			s = newRep(t, g)
		} else {
			s = newPe(t, TPE, g)
		}
		a := vmat(f17, 16, 16, 1)
		b0, b1 := vmat(f17, 16, 16, 2), vmat(f17, 16, 16, 3)
		p0, p1 := Prepare(s, g, b0), Prepare(s, g, b1)
		in := Encrypt(s, g, a, nil)
		o0, o1 := Server(s, in, p0), Server(s, in, p1)
		v0, v1 := Verifier(s, in, p0), Verifier(s, in, p1)
		if r := Verify(s, Decrypt(s, o0), v0); !r.Accepted || !reduce17(r.Out).Equal(matrix.Mul(f17, a, b0)) {
			t.Fatalf("%s honest program 0 failed: %v", c.name, r.Errors)
		}
		if r := Verify(s, Decrypt(s, o1), v1); !r.Accepted || !reduce17(r.Out).Equal(matrix.Mul(f17, a, b1)) {
			t.Fatalf("%s honest program 1 failed: %v", c.name, r.Errors)
		}
		SwapOutputs(&o0, &o1)
		if r := Verify(s, Decrypt(s, o0), v0); r.Accepted {
			t.Fatalf("%s: program-1 output accepted as program 0", c.name)
		}
		if r := Verify(s, Decrypt(s, o1), v1); r.Accepted {
			t.Fatalf("%s: program-0 output accepted as program 1", c.name)
		}
		t.Logf("%s (tiles %d): swapped program outputs rejected", c.name, in.NumTiles())
	}
}
