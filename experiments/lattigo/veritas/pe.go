package veritas

import (
	"github.com/ldsec/lattigo/v2/bfv"

	"veritas/vche/vche"
	"veritas/vche/vche_2"
)

// Pe holds a PE (polynomial encoding) session. Verification here uses the
// upstream unoptimized DecodeUint path (always available); the optimized
// polynomial protocol with client-aided re-quadratization (ReQ) is a separate,
// interactive path and is noted, not silently enabled.
type Pe struct {
	params      vche_2.Parameters
	encoder     vche_2.Encoder
	ptEncoder   vche_2.EncoderPlaintext
	encryptor   vche_2.Encryptor
	decryptor   vche_2.Decryptor
	evaluator   vche_2.Evaluator
	evaluatorPt vche_2.EvaluatorPlaintext
}

func NewPe(bfvLit bfv.ParametersLiteral) Pe {
	bfvParams, err := bfv.NewParametersFromLiteral(bfvLit)
	if err != nil {
		panic(err)
	}
	params, err := vche_2.NewParameters(bfvParams)
	if err != nil {
		panic(err)
	}
	kgen := vche_2.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 1)
	evk := &vche_2.EvaluationKey{Rlk: rlk, Rtks: nil}
	return Pe{
		params:      params,
		encoder:     vche_2.NewEncoder(params, sk.K, sk.Alpha, false),
		ptEncoder:   vche_2.NewEncoderPlaintextRequad(params, sk.K),
		encryptor:   vche_2.NewEncryptor(params, sk),
		decryptor:   vche_2.NewDecryptor(params, sk),
		evaluator:   vche_2.NewEvaluator(params, evk),
		evaluatorPt: vche_2.NewEvaluatorPlaintextRequad(params),
	}
}

func (p Pe) Slots() int { return p.params.NSlots }

type peInput struct {
	ct    *vche_2.Ciphertext
	verif *vche_2.Poly
}

func (p Pe) encrypt(values []uint64) peInput {
	coeffs := make([]uint64, p.params.NSlots)
	copy(coeffs, values)
	tags := vche.GetRandomTags(p.params.NSlots)
	pt := vche_2.NewPlaintext(p.params)
	p.encoder.EncodeUint(coeffs, tags, pt)
	return peInput{p.encryptor.EncryptNew(pt), p.ptEncoder.EncodeNew(tags)}
}

func (p Pe) decodeVerify(ct *vche_2.Ciphertext, verif *vche_2.Poly) (out []uint64, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	out = p.encoder.DecodeUintNew(p.decryptor.DecryptNew(ct), verif)
	return out, true
}

func (p Pe) Add(a, b []uint64) (out []uint64, accepted bool) {
	ina := p.encrypt(a)
	inb := p.encrypt(b)
	res := p.evaluator.AddNew(ina.ct, inb.ct)
	verif := p.evaluatorPt.AddNew(ina.verif, inb.verif)
	return p.decodeVerify(res, verif)
}

// Square uses ct*ct then relinearization; verification uses the unoptimized
// DecodeUint path. The optimized protocol would add client-aided ReQ cost.
func (p Pe) Square(a []uint64) (out []uint64, accepted bool) {
	in := p.encrypt(a)
	res := p.evaluator.MulNew(in.ct, in.ct)
	res = p.evaluator.RelinearizeNew(res)
	verif := p.evaluatorPt.MulNew(in.verif, in.verif)
	return p.decodeVerify(res, verif)
}
