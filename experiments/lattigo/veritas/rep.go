// Package veritas adapts the official VERITAS REP (vche_1) and PE (vche_2)
// encodings for matched elementwise addition and squaring on logical vectors.
// It imports the upstream code unchanged (module replace veritas/vche).
package veritas

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche"
	"veritas/vche/vche_1"
)

// Rep holds a REP (replication encoding) session at a chosen BFV parameter set
// and replication factor.
type Rep struct {
	params      vche_1.Parameters
	encoder     vche_1.Encoder
	ptEncoder   vche_1.EncoderPlaintext
	encryptor   vche_1.Encryptor
	decryptor   vche_1.Decryptor
	evaluator   vche_1.Evaluator
	evaluatorPt vche_1.EvaluatorPlaintext
}

func NewRep(bfvLit bfv.ParametersLiteral, numReplications int) Rep {
	bfvParams, err := bfv.NewParametersFromLiteral(bfvLit)
	if err != nil {
		panic(err)
	}
	params, err := vche_1.NewParameters(bfvParams, numReplications)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 1)
	evk := &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: rlk.RelinearizationKey, Rtks: nil}, H: rlk.H}
	return Rep{
		params:      params,
		encoder:     vche_1.NewEncoder(params, sk.K, sk.S, false),
		ptEncoder:   vche_1.NewEncoderPlaintext(params, sk.K),
		encryptor:   vche_1.NewEncryptor(params, sk),
		decryptor:   vche_1.NewDecryptor(params, sk),
		evaluator:   vche_1.NewEvaluator(params, evk),
		evaluatorPt: vche_1.NewEvaluatorPlaintext(params, evk.H),
	}
}

func (r Rep) Slots() int { return r.params.NSlots }

type repInput struct {
	ct    *vche_1.Ciphertext
	verif *vche_1.TaggedPoly
}

func (r Rep) encrypt(values []uint64) repInput {
	coeffs := make([]uint64, r.params.NSlots)
	copy(coeffs, values)
	tags := vche.GetRandomTags(r.params.NSlots)
	pt := vche_1.NewPlaintext(r.params)
	r.encoder.EncodeUint(coeffs, tags, pt)
	return repInput{r.encryptor.EncryptNew(pt), r.ptEncoder.EncodeNew(tags)}
}

// decodeVerify decrypts and runs the REP authentication; ok=false if the
// upstream verifier rejects (panics internally).
func (r Rep) decodeVerify(ct *vche_1.Ciphertext, verif *vche_1.TaggedPoly) (out []uint64, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	out = r.encoder.DecodeUintNew(r.decryptor.DecryptNew(ct), verif)
	return out, true
}

// Add computes a+b elementwise with REP authentication.
func (r Rep) Add(a, b []uint64) (out []uint64, accepted bool) {
	ina := r.encrypt(a)
	inb := r.encrypt(b)
	res := r.evaluator.AddNew(ina.ct, inb.ct)
	verif := r.evaluatorPt.AddNew(ina.verif, inb.verif)
	return r.decodeVerify(res, verif)
}

// Square computes a∘a elementwise (ct*ct + relin) with REP authentication.
func (r Rep) Square(a []uint64) (out []uint64, accepted bool) {
	in := r.encrypt(a)
	res := r.evaluator.MulNew(in.ct, in.ct)
	r.evaluator.Relinearize(res, res)
	verif := r.evaluatorPt.MulNew(in.verif, in.verif)
	r.evaluatorPt.Relinearize(verif, verif)
	return r.decodeVerify(res, verif)
}
