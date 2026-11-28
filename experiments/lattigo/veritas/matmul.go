// Package veritas adapts the official VERITAS REP (vche_1) and PE (vche_2)
// encodings, imported unchanged, to multiplication by a public matrix and to
// elementwise addition and squaring.
//
// The public matrix is multiplied as an unauthenticated public mask: the official
// MulScalar extended to a per-slot vector, with no secret key material. Packing is
// row-major with stride equal to the block size, tiled as
// C[I][J] = sum_K A[I][K]*B[K][J].
package veritas

import (
	"fmt"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"veritas/vche/vche_2"

	"dsfgo/bfvpack"
	"dsfgo/matrix"
)

// ProgramOps are the server operation counts of one matmul evaluation.
type ProgramOps struct{ Rotate, MulPt, Add int }

// StageHook wraps fn as a named sub-stage. A nil hook runs fn directly.
type StageHook func(name string, fn func())

func callHook(h StageHook, name string, fn func()) {
	if h == nil {
		fn()
		return
	}
	h(name, fn)
}

// Scheme is implemented by Rep and Pe; its methods are unexported so only this
// package can implement it.
type Scheme interface {
	Name() string
	LogicalSlots() int
	encryptVec(v []uint64, h StageHook) (ct, verif any)
	publicMask(coeffs []uint64) (srv, ver any)
	rotate(ct any, k int) any
	mulMask(ct, mask any) any
	add(a, b any) any
	rotateVerif(v any, k int) any
	mulVerif(v, mask any) any
	addVerif(a, b any) any
	decrypt(ct any) any
	decodeVerify(pt, verif any) ([]uint64, error)
}

// PublicMaskEncoding names the only encoding path used for public masks.
const PublicMaskEncoding = "lattigo bfv Encoder.EncodeUintMul (EncodeUintRingT -> RingTToMul)"

// CheckPlaintextModulus requires t below every Q and P prime, as in every official
// VERITAS example: RingTToMul copies coefficients into each q_i level without
// reduction.
func CheckPlaintextModulus(params bfv.Parameters) error {
	for _, q := range append(append([]uint64{}, params.Q()...), params.P()...) {
		if params.T() >= q {
			return fmt.Errorf("plaintext modulus t=%d is not below every Q/P prime (prime %d); official-example condition violated", params.T(), q)
		}
	}
	return nil
}

// Rep is a REP (replication encoding, vche_1) session.
type Rep struct {
	Params    vche_1.Parameters
	pubEnc    bfv.Encoder
	sk        *vche_1.SecretKey
	pk        *vche_1.PublicKey
	encoder   vche_1.Encoder
	ptEncoder vche_1.EncoderPlaintext
	encryptor vche_1.Encryptor
	decryptor vche_1.Decryptor
	evaluator vche_1.Evaluator
	evalPt    vche_1.EvaluatorPlaintext
	evk       *vche_1.EvaluationKey
}

// NewRepParams is stage S1: parameters and the public BFV encoder.
func NewRepParams(lit bfv.ParametersLiteral, lambda int) (*Rep, error) {
	bp, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		return nil, err
	}
	if err := CheckPlaintextModulus(bp); err != nil {
		return nil, err
	}
	p, err := vche_1.NewParameters(bp, lambda)
	if err != nil {
		return nil, err
	}
	return &Rep{Params: p, pubEnc: bfv.NewEncoder(bp)}, nil
}

// KeyGen is stage S2. The official GenSecretKey generates HE and authentication
// keys together, so they are timed as one sub-stage.
func (r *Rep) KeyGen(rotations []int, h StageHook) {
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
	callHook(h, "object_setup", func() {
		ek := rlwe.EvaluationKey{}
		if rtks != nil {
			ek.Rtks = rtks.RotationKeySet
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

func (r *Rep) Name() string      { return "veritas_rep" }
func (r *Rep) LogicalSlots() int { return r.Params.NSlots }

// EvalKeyBytes is the serialized size of the rotation keys given to the server.
func (r *Rep) EvalKeyBytes() int {
	if r.evk == nil || r.evk.Rtks == nil {
		return 0
	}
	b, err := r.evk.Rtks.MarshalBinary()
	if err != nil {
		return 0
	}
	return len(b)
}

func (r *Rep) encryptVec(v []uint64, h StageHook) (any, any) {
	var tags []vche.Tag
	pt := vche_1.NewPlaintext(r.Params)
	callHook(h, "input_auth_encode", func() {
		tags = vche.GetRandomTags(r.Params.NSlots)
		r.encoder.EncodeUint(v, tags, pt)
	})
	var ct *vche_1.Ciphertext
	callHook(h, "encrypt", func() { ct = r.encryptor.EncryptNew(pt) })
	var ver *vche_1.TaggedPoly
	callHook(h, "input_verif_poly", func() { ver = r.ptEncoder.EncodeNew(tags) })
	return ct, ver
}

// PublicMaskREP replicates each public coefficient on all lambda positions,
// dummies included, as the official MulScalar does for a scalar. Tags are empty.
func PublicMaskREP(params vche_1.Parameters, enc bfv.Encoder, coeffs []uint64) (*vche_1.PlaintextMul, *vche_1.TaggedPoly) {
	lam := params.NumReplications
	v := make([]uint64, params.N())
	for i, c := range coeffs {
		for j := 0; j < lam; j++ {
			v[i*lam+j] = c
		}
	}
	pt := vche_1.NewPlaintextMul(params)
	enc.EncodeUintMul(v, pt.PlaintextMul)
	tp := vche_1.NewTaggedPoly(params)
	params.RingT().SetCoefficientsUint64(v, tp.Poly)
	return pt, tp
}

func (r *Rep) publicMask(coeffs []uint64) (any, any) {
	return PublicMaskREP(r.Params, r.pubEnc, coeffs)
}
func (r *Rep) rotate(ct any, k int) any {
	return r.evaluator.RotateColumnsNew(ct.(*vche_1.Ciphertext), k)
}
func (r *Rep) mulMask(ct, m any) any {
	return r.evaluator.MulNew(ct.(*vche_1.Ciphertext), m.(*vche_1.PlaintextMul))
}
func (r *Rep) add(a, b any) any {
	return r.evaluator.AddNew(a.(*vche_1.Ciphertext), b.(*vche_1.Ciphertext))
}
func (r *Rep) rotateVerif(v any, k int) any {
	return r.evalPt.RotateColumnsNew(v.(*vche_1.TaggedPoly), k)
}
func (r *Rep) mulVerif(v, m any) any {
	return r.evalPt.MulNew(v.(*vche_1.TaggedPoly), m.(*vche_1.TaggedPoly))
}
func (r *Rep) addVerif(a, b any) any {
	return r.evalPt.AddNew(a.(*vche_1.TaggedPoly), b.(*vche_1.TaggedPoly))
}
func (r *Rep) decrypt(ct any) any {
	return r.decryptor.DecryptNew(ct.(*vche_1.Ciphertext))
}
func (r *Rep) decodeVerify(pt, verif any) (out []uint64, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("%v", p)
		}
	}()
	return r.encoder.DecodeUintNew(pt.(*vche_1.Plaintext), verif.(*vche_1.TaggedPoly)), nil
}

// Pe is a PE (polynomial encoding, vche_2) session.
type Pe struct {
	Params    vche_2.Parameters
	pubEnc    bfv.Encoder
	sk        *vche_2.SecretKey
	pk        *vche_2.PublicKey
	encoder   vche_2.Encoder
	ptEncoder vche_2.EncoderPlaintext
	encryptor vche_2.Encryptor
	decryptor vche_2.Decryptor
	evaluator vche_2.Evaluator
	evalPt    vche_2.EvaluatorPlaintext
	evk       *vche_2.EvaluationKey
}

// NewPeParams is stage S1 for PE (the official vche_2.NewParameters enforces
// NumReplications = 1).
func NewPeParams(lit bfv.ParametersLiteral) (*Pe, error) {
	bp, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		return nil, err
	}
	if err := CheckPlaintextModulus(bp); err != nil {
		return nil, err
	}
	p, err := vche_2.NewParameters(bp)
	if err != nil {
		return nil, err
	}
	return &Pe{Params: p, pubEnc: bfv.NewEncoder(bp)}, nil
}

// KeyGen is stage S2 for PE (same sub-stage names as REP).
func (p *Pe) KeyGen(rotations []int, h StageHook) {
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
	callHook(h, "object_setup", func() {
		p.evk = &vche_2.EvaluationKey{Rtks: rtks}
		p.encoder = vche_2.NewEncoder(p.Params, p.sk.K, p.sk.Alpha, false)
		p.ptEncoder = vche_2.NewEncoderPlaintext(p.Params, p.sk.K)
		p.encryptor = vche_2.NewEncryptor(p.Params, p.pk)
		p.decryptor = vche_2.NewDecryptor(p.Params, p.sk)
		p.evaluator = vche_2.NewEvaluator(p.Params, p.evk)
		p.evalPt = vche_2.NewEvaluatorPlaintext(p.Params)
	})
}

func (p *Pe) Name() string      { return "veritas_pe" }
func (p *Pe) LogicalSlots() int { return p.Params.NSlots }

func (p *Pe) EvalKeyBytes() int {
	if p.evk == nil || p.evk.Rtks == nil {
		return 0
	}
	b, err := p.evk.Rtks.MarshalBinary()
	if err != nil {
		return 0
	}
	return len(b)
}

func (p *Pe) encryptVec(v []uint64, h StageHook) (any, any) {
	var tags []vche.Tag
	pt := vche_2.NewPlaintext(p.Params)
	callHook(h, "input_auth_encode", func() {
		tags = vche.GetRandomTags(p.Params.NSlots)
		p.encoder.EncodeUint(v, tags, pt)
	})
	var ct *vche_2.Ciphertext
	callHook(h, "encrypt", func() { ct = p.encryptor.EncryptNew(pt) })
	var ver *vche_2.Poly
	callHook(h, "input_verif_poly", func() { ver = p.ptEncoder.EncodeNew(tags) })
	return ct, ver
}

// PublicMaskPE builds the mask as one public plaintext component (degree-0
// authenticator), which the official convolution multiplies onto every
// ciphertext component.
func PublicMaskPE(params vche_2.Parameters, enc bfv.Encoder, coeffs []uint64) (*vche_2.PlaintextMul, *vche_2.Poly) {
	v := make([]uint64, params.N())
	copy(v, coeffs)
	pt := bfv.NewPlaintextMul(params.Parameters)
	enc.EncodeUintMul(v, pt)
	poly := vche_2.NewPoly(params)
	params.RingT().SetCoefficientsUint64(v, poly.Poly)
	return &vche_2.PlaintextMul{Plaintexts: []*bfv.PlaintextMul{pt}}, poly
}

func (p *Pe) publicMask(coeffs []uint64) (any, any) {
	return PublicMaskPE(p.Params, p.pubEnc, coeffs)
}
func (p *Pe) rotate(ct any, k int) any {
	return p.evaluator.RotateColumnsNew(ct.(*vche_2.Ciphertext), k)
}
func (p *Pe) mulMask(ct, m any) any {
	return p.evaluator.MulNew(ct.(*vche_2.Ciphertext), m.(*vche_2.PlaintextMul))
}
func (p *Pe) add(a, b any) any {
	return p.evaluator.AddNew(a.(*vche_2.Ciphertext), b.(*vche_2.Ciphertext))
}
func (p *Pe) rotateVerif(v any, k int) any {
	return p.evalPt.RotateColumnsNew(v.(*vche_2.Poly), k)
}
func (p *Pe) mulVerif(v, m any) any {
	return p.evalPt.MulNew(v.(*vche_2.Poly), m.(*vche_2.Poly))
}
func (p *Pe) addVerif(a, b any) any {
	return p.evalPt.AddNew(a.(*vche_2.Poly), b.(*vche_2.Poly))
}
func (p *Pe) decrypt(ct any) any {
	return p.decryptor.DecryptNew(ct.(*vche_2.Ciphertext))
}
func (p *Pe) decodeVerify(pt, verif any) (out []uint64, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%v", r)
		}
	}()
	return p.encoder.DecodeUintNew(pt.(*vche_2.Plaintext), verif.(*vche_2.Poly)), nil
}

// Geometry is the public block geometry: row-major tiles with stride Dim = Block
// in the first slot half.
type Geometry struct {
	N, Inner, Ell, Block, Dim int
	RowOff, InnerOff, OutOff  []int
}

func uniformOff(total, tile int) []int {
	off := []int{0}
	for x := tile; x < total; x += tile {
		off = append(off, x)
	}
	return append(off, total)
}

func offLen(off []int, i int) int { return off[i+1] - off[i] }

// NewGeometry builds the geometry for an n x inner by inner x ell product
// (block >= n gives one ciphertext).
func NewGeometry(n, inner, ell, block int) Geometry {
	if block > n && block > inner && block > ell {
		block = maxInt3(n, inner, ell)
	}
	return Geometry{N: n, Inner: inner, Ell: ell, Block: block, Dim: block, RowOff: uniformOff(n, block), InnerOff: uniformOff(inner, block), OutOff: uniformOff(ell, block)}
}

func maxInt3(a, b, c int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}

func (g Geometry) IBlocks() int { return len(g.RowOff) - 1 }
func (g Geometry) KBlocks() int { return len(g.InnerOff) - 1 }
func (g Geometry) JBlocks() int { return len(g.OutOff) - 1 }

// Rotations is the union of logical rotation offsets over all block pairs.
func (g Geometry) Rotations() []int {
	return bfvpack.TiledMatmulRotations(g.Inner, g.Ell, g.Block)
}

// CheckCapacity verifies that one tile fits one logical slot half.
func (g Geometry) CheckCapacity(logicalSlots int) error {
	if g.Dim*g.Dim > logicalSlots/2 {
		return fmt.Errorf("tile stride %d needs %d slots > logical half %d", g.Dim, g.Dim*g.Dim, logicalSlots/2)
	}
	return nil
}

type maskTerm struct {
	delta    int
	srv, ver any
}

// Program holds the public masks per (inner block k, output block j); they are
// shared by all row blocks.
type Program struct {
	Geo    Geometry
	blocks [][][]maskTerm // [k][j]
	Ops    ProgramOps
}

// Prepare is stage S4 (public work: no secret key material is used).
func Prepare(s Scheme, g Geometry, b matrix.Mat) Program {
	if b.Rows() != g.Inner || b.Cols() < g.Ell {
		panic("fair public operand shape mismatch")
	}
	maxRows := 0
	for i := 0; i < g.IBlocks(); i++ {
		if l := offLen(g.RowOff, i); l > maxRows {
			maxRows = l
		}
	}
	p := Program{Geo: g, blocks: make([][][]maskTerm, g.KBlocks())}
	nTerms := make([][]int, g.KBlocks())
	nRot := make([][]int, g.KBlocks())
	for k := 0; k < g.KBlocks(); k++ {
		p.blocks[k] = make([][]maskTerm, g.JBlocks())
		nTerms[k] = make([]int, g.JBlocks())
		nRot[k] = make([]int, g.JBlocks())
		inner := offLen(g.InnerOff, k)
		for j := 0; j < g.JBlocks(); j++ {
			cols := offLen(g.OutOff, j)
			for _, delta := range append([]int{0}, bfvpack.PublicMatmulRotations(inner, cols)...) {
				coeffs := make([]uint64, s.LogicalSlots())
				nz := false
				for r := 0; r < maxRows; r++ {
					for c := 0; c < cols; c++ {
						kk := c + delta
						if kk < 0 || kk >= inner {
							continue
						}
						if v := b.At(g.InnerOff[k]+kk, g.OutOff[j]+c); v != 0 {
							coeffs[g.Dim*r+c] = v
							nz = true
						}
					}
				}
				if !nz {
					continue
				}
				srv, ver := s.publicMask(coeffs)
				p.blocks[k][j] = append(p.blocks[k][j], maskTerm{delta, srv, ver})
				nTerms[k][j]++
				if delta != 0 {
					nRot[k][j]++
				}
			}
			if nTerms[k][j] == 0 {
				panic("fair matmul block produced no terms")
			}
		}
	}
	for i := 0; i < g.IBlocks(); i++ {
		for j := 0; j < g.JBlocks(); j++ {
			for k := 0; k < g.KBlocks(); k++ {
				p.Ops.Rotate += nRot[k][j]
				p.Ops.MulPt += nTerms[k][j]
				p.Ops.Add += nTerms[k][j] - 1
			}
			p.Ops.Add += g.KBlocks() - 1
		}
	}
	return p
}

// Input is the client upload: one ciphertext per tile [i][k] and the verifier's
// verification polynomials.
type Input struct {
	Geo  Geometry
	cts  [][]any
	vers [][]any
}

func (in Input) NumTiles() int { return in.Geo.IBlocks() * in.Geo.KBlocks() }

// Encrypt is stage S5. Sub-stages accumulate across tiles.
func Encrypt(s Scheme, g Geometry, a matrix.Mat, h StageHook) Input {
	if a.Rows() != g.N || a.Cols() != g.Inner {
		panic("fair confidential operand shape mismatch")
	}
	in := Input{Geo: g, cts: make([][]any, g.IBlocks()), vers: make([][]any, g.IBlocks())}
	for i := 0; i < g.IBlocks(); i++ {
		in.cts[i] = make([]any, g.KBlocks())
		in.vers[i] = make([]any, g.KBlocks())
		for k := 0; k < g.KBlocks(); k++ {
			v := make([]uint64, s.LogicalSlots())
			for r := 0; r < offLen(g.RowOff, i); r++ {
				for c := 0; c < offLen(g.InnerOff, k); c++ {
					v[g.Dim*r+c] = a.At(g.RowOff[i]+r, g.InnerOff[k]+c)
				}
			}
			in.cts[i][k], in.vers[i][k] = s.encryptVec(v, h)
		}
	}
	return in
}

// Output is the server result: one ciphertext per output tile [i][j].
type Output struct {
	Geo Geometry
	cts [][]any
}

func (o Output) NumTiles() int { return o.Geo.IBlocks() * o.Geo.JBlocks() }

func evalBlock(s Scheme, ct any, terms []maskTerm) any {
	var acc any
	for _, t := range terms {
		src := ct
		if t.delta != 0 {
			src = s.rotate(ct, t.delta)
		}
		term := s.mulMask(src, t.srv)
		if acc == nil {
			acc = term
		} else {
			acc = s.add(acc, term)
		}
	}
	return acc
}

// Server is stage S6: server-only evaluation, loop order i -> j -> k as
// bfvpack.ServerTiledMatmul.
func Server(s Scheme, in Input, p Program) Output {
	g := p.Geo
	out := Output{Geo: g, cts: make([][]any, g.IBlocks())}
	for i := 0; i < g.IBlocks(); i++ {
		out.cts[i] = make([]any, g.JBlocks())
		for j := 0; j < g.JBlocks(); j++ {
			var acc any
			for k := 0; k < g.KBlocks(); k++ {
				term := evalBlock(s, in.cts[i][k], p.blocks[k][j])
				if acc == nil {
					acc = term
				} else {
					acc = s.add(acc, term)
				}
			}
			out.cts[i][j] = acc
		}
	}
	return out
}

// Verif holds the verifier's expected-tag state per output tile.
type Verif struct{ vers [][]any }

func verifBlock(s Scheme, v any, terms []maskTerm) any {
	var acc any
	for _, t := range terms {
		src := v
		if t.delta != 0 {
			src = s.rotateVerif(v, t.delta)
		}
		term := s.mulVerif(src, t.ver)
		if acc == nil {
			acc = term
		} else {
			acc = s.addVerif(acc, term)
		}
	}
	return acc
}

// Verifier is stage S7: verifier-side evolution mirroring Server.
func Verifier(s Scheme, in Input, p Program) Verif {
	g := p.Geo
	out := Verif{vers: make([][]any, g.IBlocks())}
	for i := 0; i < g.IBlocks(); i++ {
		out.vers[i] = make([]any, g.JBlocks())
		for j := 0; j < g.JBlocks(); j++ {
			var acc any
			for k := 0; k < g.KBlocks(); k++ {
				term := verifBlock(s, in.vers[i][k], p.blocks[k][j])
				if acc == nil {
					acc = term
				} else {
					acc = s.addVerif(acc, term)
				}
			}
			out.vers[i][j] = acc
		}
	}
	return out
}

// Decrypted holds decrypted output tiles (stage S8 result).
type Decrypted struct {
	Geo Geometry
	pts [][]any
}

// Decrypt is stage S8.
func Decrypt(s Scheme, o Output) Decrypted {
	d := Decrypted{Geo: o.Geo, pts: make([][]any, len(o.cts))}
	for i := range o.cts {
		d.pts[i] = make([]any, len(o.cts[i]))
		for j := range o.cts[i] {
			d.pts[i][j] = s.decrypt(o.cts[i][j])
		}
	}
	return d
}

// Result is the verified, reassembled n x ell output.
type Result struct {
	Out      matrix.Mat
	Accepted bool
	Errors   []string // per rejected tile, "tile(i,j): message"
}

// Verify is stage S9: official verification and decoding per tile; acceptance is
// the AND over tiles.
func Verify(s Scheme, d Decrypted, v Verif) Result {
	g := d.Geo
	res := Result{Out: matrix.New(g.N, g.Ell), Accepted: true}
	for i := range d.pts {
		for j := range d.pts[i] {
			vals, err := s.decodeVerify(d.pts[i][j], v.vers[i][j])
			if err != nil {
				res.Accepted = false
				res.Errors = append(res.Errors, fmt.Sprintf("tile(%d,%d): %v", i, j, err))
				continue
			}
			for r := 0; r < offLen(g.RowOff, i); r++ {
				for c := 0; c < offLen(g.OutOff, j); c++ {
					res.Out.Set(g.RowOff[i]+r, g.OutOff[j]+c, vals[g.Dim*r+c])
				}
			}
		}
	}
	if !res.Accepted {
		res.Out = matrix.New(g.N, g.Ell)
	}
	return res
}

// CiphertextBytes sums the BFV payloads of all tiles (REP tags and PE framing excluded).
func CiphertextBytes(tiles [][]any) int {
	total := 0
	for _, row := range tiles {
		for _, ct := range row {
			switch c := ct.(type) {
			case *vche_1.Ciphertext:
				if b, err := c.Ciphertext.MarshalBinary(); err == nil {
					total += len(b)
				}
			case *vche_2.Ciphertext:
				for _, part := range c.Ciphertexts {
					if b, err := part.MarshalBinary(); err == nil {
						total += len(b)
					}
				}
			}
		}
	}
	return total
}

// InputCiphertexts / OutputCiphertexts expose tiles for size accounting.
func (in Input) InputCiphertexts() [][]any  { return in.cts }
func (o Output) OutputCiphertexts() [][]any { return o.cts }
