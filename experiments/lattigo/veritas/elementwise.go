package veritas

// Elementwise addition and squaring on a confidential n x 1 vector. Squaring is
// ct x ct and is the only operation that needs a relinearisation key.

import (
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche_1"
	"veritas/vche/vche_2"
)

// KeyGenRelin is KeyGen with an optional relinearisation key (sub-stage relin_keygen).
func (r *Rep) KeyGenRelin(rotations []int, relin bool, h StageHook) {
	var kgen vche_1.KeyGenerator
	callHook(h, "keygen_object", func() { kgen = vche_1.NewKeyGenerator(r.Params) })
	callHook(h, "he_and_auth_secret_keygen", func() { r.sk = kgen.GenSecretKey() })
	callHook(h, "public_keygen", func() { r.pk = kgen.GenPublicKey(r.sk) })
	var rtks *vche_1.RotationKeySet
	callHook(h, "rotation_keygen", func() {
		if len(rotations) > 0 {
			rtks = kgen.GenRotationKeysForRotations(rotations, false, r.sk)
		}
	})
	var rlk *vche_1.RelinearizationKey
	if relin {
		callHook(h, "relin_keygen", func() { rlk = kgen.GenRelinearizationKey(r.sk, 1) })
	}
	callHook(h, "object_setup", func() {
		ek := rlwe.EvaluationKey{}
		if rtks != nil {
			ek.Rtks = rtks.RotationKeySet
		}
		if rlk != nil {
			ek.Rlk = rlk.RelinearizationKey
		}
		r.evk = &vche_1.EvaluationKey{EvaluationKey: ek, H: r.sk.H}
		r.encoder = vche_1.NewEncoder(r.Params, r.sk.K, r.sk.S, false)
		r.ptEncoder = vche_1.NewEncoderPlaintext(r.Params, r.sk.K)
		r.encryptor = vche_1.NewEncryptor(r.Params, r.pk)
		r.decryptor = vche_1.NewDecryptor(r.Params, r.sk)
		r.evaluator = vche_1.NewEvaluator(r.Params, r.evk)
		r.evalPt = vche_1.NewEvaluatorPlaintext(r.Params, r.evk.H)
	})
}

// KeyGenRelin for PE.
func (p *Pe) KeyGenRelin(rotations []int, relin bool, h StageHook) {
	var kgen vche_2.KeyGenerator
	callHook(h, "keygen_object", func() { kgen = vche_2.NewKeyGenerator(p.Params) })
	callHook(h, "he_and_auth_secret_keygen", func() { p.sk = kgen.GenSecretKey() })
	callHook(h, "public_keygen", func() { p.pk = kgen.GenPublicKey(p.sk) })
	var rtks *vche_2.RotationKeySet
	callHook(h, "rotation_keygen", func() {
		if len(rotations) > 0 {
			rtks = kgen.GenRotationKeysForRotations(rotations, false, p.sk)
		}
	})
	var rlk *vche_2.RelinearizationKey
	if relin {
		callHook(h, "relin_keygen", func() { rlk = kgen.GenRelinearizationKey(p.sk, 1) })
	}
	callHook(h, "object_setup", func() {
		p.evk = &vche_2.EvaluationKey{Rtks: rtks, Rlk: rlk}
		p.encoder = vche_2.NewEncoder(p.Params, p.sk.K, p.sk.Alpha, false)
		p.ptEncoder = vche_2.NewEncoderPlaintext(p.Params, p.sk.K)
		p.encryptor = vche_2.NewEncryptor(p.Params, p.pk)
		p.decryptor = vche_2.NewDecryptor(p.Params, p.sk)
		p.evaluator = vche_2.NewEvaluator(p.Params, p.evk)
		p.evalPt = vche_2.NewEvaluatorPlaintext(p.Params)
	})
}

// ElementInput is one encrypted vector and its verification state.
type ElementInput struct{ ct, ver any }

// EncryptVector encrypts the first len(v) logical slots (rest zero).
func EncryptVector(s Scheme, v []uint64, h StageHook) ElementInput {
	slots := make([]uint64, s.LogicalSlots())
	copy(slots, v)
	ct, ver := s.encryptVec(slots, h)
	return ElementInput{ct, ver}
}

// ElementResult carries the server output and verifier state of one op.
type ElementResult struct{ ct, ver, pt any }

// ElementServer is the server-only operation (add | square).
func ElementServer(s Scheme, op string, a, d ElementInput) ElementResult {
	switch x := s.(type) {
	case *Rep:
		if op == "add" {
			return ElementResult{ct: x.evaluator.AddNew(a.ct.(*vche_1.Ciphertext), d.ct.(*vche_1.Ciphertext))}
		}
		ct := x.evaluator.MulNew(a.ct.(*vche_1.Ciphertext), a.ct.(*vche_1.Ciphertext))
		x.evaluator.Relinearize(ct, ct)
		return ElementResult{ct: ct}
	case *Pe:
		if op == "add" {
			return ElementResult{ct: x.evaluator.AddNew(a.ct.(*vche_2.Ciphertext), d.ct.(*vche_2.Ciphertext))}
		}
		ct := x.evaluator.MulNew(a.ct.(*vche_2.Ciphertext), a.ct.(*vche_2.Ciphertext))
		return ElementResult{ct: x.evaluator.RelinearizeNew(ct)}
	}
	panic("unknown scheme")
}

// ElementVerifier mirrors ElementServer on the verifier state.
func ElementVerifier(s Scheme, op string, a, d ElementInput, res *ElementResult) {
	switch x := s.(type) {
	case *Rep:
		if op == "add" {
			res.ver = x.evalPt.AddNew(a.ver.(*vche_1.TaggedPoly), d.ver.(*vche_1.TaggedPoly))
			return
		}
		v := x.evalPt.MulNew(a.ver.(*vche_1.TaggedPoly), a.ver.(*vche_1.TaggedPoly))
		x.evalPt.Relinearize(v, v)
		res.ver = v
	case *Pe:
		if op == "add" {
			res.ver = x.evalPt.AddNew(a.ver.(*vche_2.Poly), d.ver.(*vche_2.Poly))
			return
		}
		res.ver = x.evalPt.MulNew(a.ver.(*vche_2.Poly), a.ver.(*vche_2.Poly))
	}
}

// ElementDecrypt is the client decryption (S8).
func ElementDecrypt(s Scheme, res *ElementResult) { res.pt = s.decrypt(res.ct) }

// ElementVerify is the official verification and decode (S9).
func ElementVerify(s Scheme, res ElementResult, n int) ([]uint64, error) {
	vals, err := s.decodeVerify(res.pt, res.ver)
	if err != nil {
		return nil, err
	}
	return vals[:n], nil
}

// ElementBytes returns underlying BFV payload sizes of inputs and output.
func ElementBytes(res ElementResult, inputs ...ElementInput) (int, int) {
	in := 0
	for _, x := range inputs {
		in += CiphertextBytes([][]any{{x.ct}})
	}
	return in, CiphertextBytes([][]any{{res.ct}})
}

func (r *Rep) RelinKeyPresent() bool { return r.evk != nil && r.evk.Rlk != nil }
func (p *Pe) RelinKeyPresent() bool  { return p.evk != nil && p.evk.Rlk != nil }

// SwapOutputs exchanges the outputs of two programs (tamper test helper).
func SwapOutputs(a, b *Output) { a.cts, b.cts = b.cts, a.cts }
