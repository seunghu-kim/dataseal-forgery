package veritas

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"veritas/vche/vche_2"

	"dsfgo/bfvpack"
	"dsfgo/matrix"
)

// Authenticated public-right matrix multiplication C = A*B (A confidential, B
// public) built only from official VERITAS operations: authenticated
// RotateColumns, ciphertext-by-tagged-plaintext Mul, and Add, mirrored on the
// official EvaluatorPlaintext tag machinery, then checked by the official
// DecodeUint verifier. The circuit is the same row-major block-diagonal linear
// transform used by bfvpack.
//
// Phases are split so the benchmark can attribute each cost to its legitimate
// party and never counts client/verifier work as server evaluation:
//   - ClientEncrypt: per-input encoding + encryption + input tag polynomial.
//   - PrepareProgram: public, program-specific mask encoding + mask tag poly.
//   - ServerEval: server-only ciphertext evaluation (ct + public masks +
//     rotation keys). Its signature takes no verification poly and no secret.
//   - VerifierTags: verifier-only tag evolution (verif poly + public masks).
//   - DecodeVerify: decrypt + official verification (needs the secret key).

// rowMajorPack lays an r x c logical matrix into nslots with row stride dim.
func rowMajorPack(m matrix.Mat, dim, nslots int) []uint64 {
	v := make([]uint64, nslots)
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			v[dim*i+j] = m.At(i, j)
		}
	}
	return v
}

// MatmulCapacity reports the largest square stride dim that keeps a row-major
// layout inside one logical half (nslots/2), so authenticated RotateColumns
// never crosses the half boundary.
func MatmulCapacity(nslots int) int { return nslots / 2 }

// RotationsFor returns the logical column offsets a public-right matmul needs.
func RotationsFor(inner, ell int) []int { return bfvpack.PublicMatmulRotations(inner, ell) }

// ProgramOps are the server operation counts for one authenticated matmul
// evaluation (per single evaluation, derived from the program structure).
type ProgramOps struct{ Rotate, MulPt, Add int }

func opsFromTermCount(nTerms, nRot int) ProgramOps {
	adds := 0
	if nTerms > 0 {
		adds = nTerms - 1
	}
	return ProgramOps{Rotate: nRot, MulPt: nTerms, Add: adds}
}

// maskPlan is the geometry of the program masks, shared by REP and PE term
// construction. deltas[i] with coeffs nonzero -> one term.
type termPlan struct {
	delta  int
	coeffs []uint64
}

func buildTermPlans(b matrix.Mat, n, ell, dim, nslots int) []termPlan {
	inner := b.Rows()
	var plans []termPlan
	for _, delta := range append([]int{0}, bfvpack.PublicMatmulRotations(inner, ell)...) {
		mask := make([]uint64, nslots)
		nz := false
		for i := 0; i < n; i++ {
			for j := 0; j < ell; j++ {
				kk := j + delta
				if kk < 0 || kk >= inner {
					continue
				}
				if c := b.At(kk, j); c != 0 {
					mask[dim*i+j] = c
					nz = true
				}
			}
		}
		if nz {
			plans = append(plans, termPlan{delta, mask})
		}
	}
	return plans
}

// --- REP (vche_1) ---

type RepMatmul struct {
	params      vche_1.Parameters
	encoder     vche_1.Encoder
	ptEncoder   vche_1.EncoderPlaintext
	encryptor   vche_1.Encryptor
	decryptor   vche_1.Decryptor
	evaluator   vche_1.Evaluator
	evaluatorPt vche_1.EvaluatorPlaintext
	NSlots      int
}

// NewRepMatmul builds a REP session with rotation keys for the given logical
// column offsets. numReplications must be > 1 for nondegenerate authentication.
func NewRepMatmul(bfvLit bfv.ParametersLiteral, numReplications int, rotations []int) RepMatmul {
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
	rtks := kgen.GenRotationKeysForRotations(rotations, true, sk)
	evk := &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: rlk.RelinearizationKey, Rtks: rtks.RotationKeySet}, H: sk.H}
	return RepMatmul{
		params:      params,
		encoder:     vche_1.NewEncoder(params, sk.K, sk.S, false),
		ptEncoder:   vche_1.NewEncoderPlaintext(params, sk.K),
		encryptor:   vche_1.NewEncryptor(params, sk),
		decryptor:   vche_1.NewDecryptor(params, sk),
		evaluator:   vche_1.NewEvaluator(params, evk),
		evaluatorPt: vche_1.NewEvaluatorPlaintext(params, evk.H),
		NSlots:      params.NSlots,
	}
}

// RepInput is the client output: a ciphertext for the server and the matching
// input verification polynomial held by the verifier.
type RepInput struct {
	Ct    *vche_1.Ciphertext
	Verif *vche_1.TaggedPoly
}

type repTerm struct {
	delta   int
	mask    *vche_1.PlaintextMul
	maskVer *vche_1.TaggedPoly
}

// RepProgram is the public, program-specific prepared data (pre-encoded masks
// and their tag polynomials). It carries no secret or input-dependent state.
type RepProgram struct {
	terms       []repTerm
	nRot        int
	n, ell, dim int
}

// Ops returns the per-single-evaluation server operation counts.
func (p RepProgram) Ops() ProgramOps { return opsFromTermCount(len(p.terms), p.nRot) }

// ClientEncrypt performs per-input encoding, encryption, and input tag poly.
func (r RepMatmul) ClientEncrypt(a matrix.Mat, dim int) RepInput {
	if dim*dim > r.NSlots/2 {
		panic("rep matmul layout exceeds nslots")
	}
	inTags := vche.GetRandomTags(r.NSlots)
	pt := vche_1.NewPlaintext(r.params)
	r.encoder.EncodeUint(rowMajorPack(a, dim, r.NSlots), inTags, pt)
	return RepInput{r.encryptor.EncryptNew(pt), r.ptEncoder.EncodeNew(inTags)}
}

// PrepareProgram pre-encodes the public masks and their tag polynomials.
func (r RepMatmul) PrepareProgram(b matrix.Mat, n, ell, dim int) RepProgram {
	maskTags := vche.GetRandomTags(r.NSlots)
	maskVer := r.ptEncoder.EncodeNew(maskTags)
	plans := buildTermPlans(b, n, ell, dim, r.NSlots)
	prog := RepProgram{n: n, ell: ell, dim: dim}
	for _, pl := range plans {
		prog.terms = append(prog.terms, repTerm{pl.delta, r.encoder.EncodeUintMulNew(pl.coeffs, maskTags), maskVer})
		if pl.delta != 0 {
			prog.nRot++
		}
	}
	if len(prog.terms) == 0 {
		panic("rep matmul produced no terms")
	}
	return prog
}

// ServerEval is the server-only evaluation: ciphertext, public pre-encoded
// masks, and rotation keys. No verification poly, no secret key in scope.
func (r RepMatmul) ServerEval(ct *vche_1.Ciphertext, prog RepProgram) *vche_1.Ciphertext {
	var acc *vche_1.Ciphertext
	for _, t := range prog.terms {
		src := ct
		if t.delta != 0 {
			src = r.evaluator.RotateColumnsNew(ct, t.delta)
		}
		term := r.evaluator.MulNew(src, t.mask)
		if acc == nil {
			acc = term
		} else {
			acc = r.evaluator.AddNew(acc, term)
		}
	}
	return acc
}

// VerifierTags is the verifier-only tag evolution mirroring the server circuit.
func (r RepMatmul) VerifierTags(verif *vche_1.TaggedPoly, prog RepProgram) *vche_1.TaggedPoly {
	var acc *vche_1.TaggedPoly
	for _, t := range prog.terms {
		src := verif
		if t.delta != 0 {
			src = r.evaluatorPt.RotateColumnsNew(verif, t.delta)
		}
		term := r.evaluatorPt.MulNew(src, t.maskVer)
		if acc == nil {
			acc = term
		} else {
			acc = r.evaluatorPt.AddNew(acc, term)
		}
	}
	return acc
}

// DecodeVerify decrypts and runs the official verification. On a rejected tag
// check the upstream verifier panics; this is recovered and reported as
// accepted=false without dereferencing a nil decoded vector.
func (r RepMatmul) DecodeVerify(ct *vche_1.Ciphertext, verif *vche_1.TaggedPoly, prog RepProgram) (out matrix.Mat, accepted bool) {
	outv, ok := r.decode(ct, verif)
	if !ok || outv == nil {
		return matrix.New(prog.n, prog.ell), false
	}
	out = matrix.New(prog.n, prog.ell)
	for i := 0; i < prog.n; i++ {
		for j := 0; j < prog.ell; j++ {
			out.Set(i, j, outv[prog.dim*i+j])
		}
	}
	return out, true
}

func (r RepMatmul) decode(ct *vche_1.Ciphertext, verif *vche_1.TaggedPoly) (out []uint64, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()
	out = r.encoder.DecodeUintNew(r.decryptor.DecryptNew(ct), verif)
	return out, true
}

// PublicRightMatmul is a convenience wrapper running every phase in-process.
func (r RepMatmul) PublicRightMatmul(a, b matrix.Mat, dim int) (out matrix.Mat, accepted bool) {
	n, ell := a.Rows(), b.Cols()
	in := r.ClientEncrypt(a, dim)
	prog := r.PrepareProgram(b, n, ell, dim)
	ct := r.ServerEval(in.Ct, prog)
	verif := r.VerifierTags(in.Verif, prog)
	return r.DecodeVerify(ct, verif, prog)
}

// --- PE (vche_2) ---

type PeMatmul struct {
	params      vche_2.Parameters
	encoder     vche_2.Encoder
	ptEncoder   vche_2.EncoderPlaintext
	encryptor   vche_2.Encryptor
	decryptor   vche_2.Decryptor
	evaluator   vche_2.Evaluator
	evaluatorPt vche_2.EvaluatorPlaintext
	NSlots      int
}

func NewPeMatmul(bfvLit bfv.ParametersLiteral, rotations []int) PeMatmul {
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
	rtks := kgen.GenRotationKeysForRotations(rotations, true, sk)
	evk := &vche_2.EvaluationKey{Rlk: rlk, Rtks: rtks}
	return PeMatmul{
		params:      params,
		encoder:     vche_2.NewEncoder(params, sk.K, sk.Alpha, false),
		ptEncoder:   vche_2.NewEncoderPlaintext(params, sk.K),
		encryptor:   vche_2.NewEncryptor(params, sk),
		decryptor:   vche_2.NewDecryptor(params, sk),
		evaluator:   vche_2.NewEvaluator(params, evk),
		evaluatorPt: vche_2.NewEvaluatorPlaintext(params),
		NSlots:      params.NSlots,
	}
}

type PeInput struct {
	Ct    *vche_2.Ciphertext
	Verif *vche_2.Poly
}

type peTerm struct {
	delta   int
	mask    *vche_2.PlaintextMul
	maskVer *vche_2.Poly
}

type PeProgram struct {
	terms       []peTerm
	nRot        int
	n, ell, dim int
}

func (p PeProgram) Ops() ProgramOps { return opsFromTermCount(len(p.terms), p.nRot) }

func (p PeMatmul) ClientEncrypt(a matrix.Mat, dim int) PeInput {
	if dim*dim > p.NSlots/2 {
		panic("pe matmul layout exceeds nslots")
	}
	inTags := vche.GetRandomTags(p.NSlots)
	pt := vche_2.NewPlaintext(p.params)
	p.encoder.EncodeUint(rowMajorPack(a, dim, p.NSlots), inTags, pt)
	return PeInput{p.encryptor.EncryptNew(pt), p.ptEncoder.EncodeNew(inTags)}
}

func (p PeMatmul) PrepareProgram(b matrix.Mat, n, ell, dim int) PeProgram {
	maskTags := vche.GetRandomTags(p.NSlots)
	maskVer := p.ptEncoder.EncodeNew(maskTags)
	plans := buildTermPlans(b, n, ell, dim, p.NSlots)
	prog := PeProgram{n: n, ell: ell, dim: dim}
	for _, pl := range plans {
		prog.terms = append(prog.terms, peTerm{pl.delta, p.encoder.EncodeUintMulNew(pl.coeffs, maskTags), maskVer})
		if pl.delta != 0 {
			prog.nRot++
		}
	}
	if len(prog.terms) == 0 {
		panic("pe matmul produced no terms")
	}
	return prog
}

func (p PeMatmul) ServerEval(ct *vche_2.Ciphertext, prog PeProgram) *vche_2.Ciphertext {
	var acc *vche_2.Ciphertext
	for _, t := range prog.terms {
		src := ct
		if t.delta != 0 {
			src = p.evaluator.RotateColumnsNew(ct, t.delta)
		}
		term := p.evaluator.MulNew(src, t.mask)
		if acc == nil {
			acc = term
		} else {
			acc = p.evaluator.AddNew(acc, term)
		}
	}
	return acc
}

func (p PeMatmul) VerifierTags(verif *vche_2.Poly, prog PeProgram) *vche_2.Poly {
	var acc *vche_2.Poly
	for _, t := range prog.terms {
		src := verif
		if t.delta != 0 {
			src = p.evaluatorPt.RotateColumnsNew(verif, t.delta)
		}
		term := p.evaluatorPt.MulNew(src, t.maskVer)
		if acc == nil {
			acc = term
		} else {
			acc = p.evaluatorPt.AddNew(acc, term)
		}
	}
	return acc
}

func (p PeMatmul) DecodeVerify(ct *vche_2.Ciphertext, verif *vche_2.Poly, prog PeProgram) (out matrix.Mat, accepted bool) {
	outv, ok := p.decode(ct, verif)
	if !ok || outv == nil {
		return matrix.New(prog.n, prog.ell), false
	}
	out = matrix.New(prog.n, prog.ell)
	for i := 0; i < prog.n; i++ {
		for j := 0; j < prog.ell; j++ {
			out.Set(i, j, outv[prog.dim*i+j])
		}
	}
	return out, true
}

func (p PeMatmul) decode(ct *vche_2.Ciphertext, verif *vche_2.Poly) (out []uint64, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()
	out = p.encoder.DecodeUintNew(p.decryptor.DecryptNew(ct), verif)
	return out, true
}

func (p PeMatmul) PublicRightMatmul(a, b matrix.Mat, dim int) (out matrix.Mat, accepted bool) {
	n, ell := a.Rows(), b.Cols()
	in := p.ClientEncrypt(a, dim)
	prog := p.PrepareProgram(b, n, ell, dim)
	ct := p.ServerEval(in.Ct, prog)
	verif := p.VerifierTags(in.Verif, prog)
	return p.DecodeVerify(ct, verif, prog)
}
