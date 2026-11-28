// Package bfvpack implements row-major packed BFV matrix operations on Lattigo.
// Multiplication by a public matrix uses rotations and plaintext masks only.
package bfvpack

import (
	"sort"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"

	"dsfgo/field"
	"dsfgo/matrix"
)

type Context struct {
	Params  bfv.Parameters
	encoder bfv.Encoder
	field   field.Field
}

// NewContext uses PN14QP438 (N=16384, t=65537), the common profile.
func NewContext() Context { return NewContextWith(bfv.PN14QP438) }

// NewContextWith takes an explicit parameter set; all pinned sets use t=65537.
func NewContextWith(lit bfv.ParametersLiteral) Context {
	params, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		panic(err)
	}
	return Context{params, bfv.NewEncoder(params), field.New(params.T())}
}

func (c Context) Field() field.Field { return c.field }
func (c Context) Slots() int         { return int(c.Params.N()) }
func (c Context) RowSlots() int      { return int(c.Params.N()) / 2 }

type Layout struct {
	LogicalRows, LogicalCols int
	DataRows                 int
	Dim                      int
}

func MakeLayout(logicalRows, logicalCols, dataRows, dim int) Layout {
	if logicalRows > dim || logicalCols > dim {
		panic("layout exceeds padded dimension")
	}
	if dataRows > logicalRows {
		panic("data rows exceed logical rows")
	}
	return Layout{logicalRows, logicalCols, dataRows, dim}
}

func (l Layout) slot(i, j int) int { return l.Dim*i + j }
func (l Layout) Slot(i, j int) int { return l.Dim*i + j }
func (l Layout) slotCount() int    { return l.Dim * l.Dim }

type Counts struct{ Add, MulPt, MulCt, Rotate int }

type Keys struct {
	sk    *rlwe.SecretKey
	Pk    *rlwe.PublicKey
	eval  bfv.Evaluator
	ek    rlwe.EvaluationKey
	Rots  []int
	Relin bool
	ctx   Context
	Count *Counts
	Meter *OperationMeter // optional operation meter; nil by default
}

func (k Keys) ResetCount() { *k.Count = Counts{} }

func (k Keys) CountSnapshot() Counts { return *k.Count }

// Capability describes which evaluation keys the server is given.
type Capability struct {
	Relin     bool
	Rotations []int
}

func (c Context) KeyGen(cap Capability) Keys {
	kgen := bfv.NewKeyGenerator(c.Params)
	sk, pk := kgen.GenKeyPair()
	ek := rlwe.EvaluationKey{}
	if cap.Relin {
		ek.Rlk = kgen.GenRelinearizationKey(sk, 1)
	}
	if len(cap.Rotations) > 0 {
		ek.Rtks = kgen.GenRotationKeysForRotations(cap.Rotations, false, sk)
	}
	return Keys{sk: sk, Pk: pk, eval: bfv.NewEvaluator(c.Params, ek), ek: ek, Rots: cap.Rotations, Relin: cap.Relin, ctx: c, Count: &Counts{}}
}

func (c Cipher) Bytes() int {
	b, err := c.ct.MarshalBinary()
	if err != nil {
		return 0
	}
	return len(b)
}

// EvalKeyBytes is the serialized size of the server's evaluation keys, reported
// separately from online compute.
func (k Keys) EvalKeyBytes() int {
	total := 0
	if k.ek.Rlk != nil {
		if b, err := k.ek.Rlk.MarshalBinary(); err == nil {
			total += len(b)
		}
	}
	if k.ek.Rtks != nil {
		if b, err := k.ek.Rtks.MarshalBinary(); err == nil {
			total += len(b)
		}
	}
	return total
}

type Cipher struct {
	Layout Layout
	ct     *bfv.Ciphertext
}

func (c Context) pack(m matrix.Mat, l Layout) []uint64 {
	if m.Rows() != l.LogicalRows || m.Cols() != l.LogicalCols {
		panic("matrix shape does not match layout")
	}
	if l.slotCount() > c.RowSlots() {
		panic("layout does not fit into one rotation row")
	}
	v := make([]uint64, c.Slots())
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			v[l.slot(i, j)] = m.At(i, j)
		}
	}
	return v
}

func (k Keys) Encrypt(m matrix.Mat, l Layout) Cipher {
	pt := bfv.NewPlaintext(k.ctx.Params)
	k.ctx.encoder.EncodeUint(k.ctx.pack(m, l), pt)
	enc := bfv.NewEncryptor(k.ctx.Params, k.Pk)
	return Cipher{l, enc.EncryptNew(pt)}
}

func (k Keys) Decrypt(c Cipher) matrix.Mat {
	dec := bfv.NewDecryptor(k.ctx.Params, k.sk)
	out := make([]uint64, k.ctx.Slots())
	k.ctx.encoder.DecodeUint(dec.DecryptNew(c.ct), out)
	m := matrix.New(c.Layout.LogicalRows, c.Layout.LogicalCols)
	for i := 0; i < c.Layout.LogicalRows; i++ {
		for j := 0; j < c.Layout.LogicalCols; j++ {
			m.Set(i, j, out[c.Layout.slot(i, j)])
		}
	}
	// padding check: logical region beyond used rows/cols must stay zero
	for i := 0; i < c.Layout.LogicalRows; i++ {
		for j := c.Layout.LogicalCols; j < c.Layout.Dim; j++ {
			if out[c.Layout.slot(i, j)] != 0 {
				panic("nonzero padding slot")
			}
		}
	}
	return m
}

func (k Keys) maskPt(mask []uint64) *bfv.PlaintextMul {
	pt := bfv.NewPlaintextMul(k.ctx.Params)
	k.ctx.encoder.EncodeUintMul(mask, pt)
	return pt
}

// PublicMatmulRotations returns the rotation offsets k-j for the layout.
func PublicMatmulRotations(inner, outCols int) []int {
	set := map[int]bool{}
	for k := 0; k < inner; k++ {
		for j := 0; j < outCols; j++ {
			d := k - j
			if d != 0 {
				set[d] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Ints(out)
	return out
}

// maskTerm is one program term: rotate by Delta, then multiply by a mask. Masks
// are encoded once during preparation, outside server timing.
type maskTerm struct {
	Delta int
	Mask  *bfv.PlaintextMul
}

// PreparedMatmul is the public program for multiplication by B: encoded masks and
// the output layout, with no secret or input-dependent state.
type PreparedMatmul struct {
	terms     []maskTerm
	outLayout Layout
	rotations []int
}

// PrepareMatmul builds one mask per rotation offset (a diagonal of B).
func (k Keys) PrepareMatmul(inLayout Layout, b matrix.Mat, outCols int) PreparedMatmul {
	inner := inLayout.LogicalCols
	if b.Rows() != inner {
		panic("public matmul inner dimension mismatch")
	}
	if outCols > b.Cols() || outCols > inLayout.Dim {
		panic("output columns exceed operand or padded dim")
	}
	var p PreparedMatmul
	p.outLayout = MakeLayout(inLayout.LogicalRows, outCols, inLayout.DataRows, inLayout.Dim)
	rotset := map[int]bool{}
	for _, delta := range append([]int{0}, PublicMatmulRotations(inner, outCols)...) {
		mask := make([]uint64, k.ctx.Slots())
		nonzero := false
		for i := 0; i < inLayout.LogicalRows; i++ {
			for j := 0; j < outCols; j++ {
				kk := j + delta
				if kk < 0 || kk >= inner {
					continue
				}
				if coeff := b.At(kk, j); coeff != 0 {
					mask[inLayout.slot(i, j)] = coeff
					nonzero = true
				}
			}
		}
		if !nonzero {
			continue
		}
		p.terms = append(p.terms, maskTerm{delta, k.maskPt(mask)})
		if delta != 0 {
			rotset[delta] = true
		}
	}
	for d := range rotset {
		p.rotations = append(p.rotations, d)
	}
	sort.Ints(p.rotations)
	return p
}

// ServerMatmul evaluates a prepared program with server-visible objects only. It
// adds to k.Count without resetting, so counts accumulate under tiling.
func (k Keys) ServerMatmul(a Cipher, p PreparedMatmul) Cipher {
	var acc *bfv.Ciphertext
	for _, t := range p.terms {
		src := a.ct
		if t.Delta != 0 {
			src = k.eval.RotateColumnsNew(a.ct, t.Delta)
			k.Count.Rotate++
		}
		term := k.eval.MulNew(src, t.Mask)
		k.Count.MulPt++
		if acc == nil {
			acc = term
		} else {
			k.eval.Add(acc, term, acc)
			k.Count.Add++
		}
	}
	if acc == nil {
		panic("public matmul produced no terms")
	}
	return Cipher{p.outLayout, acc}
}

// PublicRightMatmul is PrepareMatmul followed by ServerMatmul.
func (k Keys) PublicRightMatmul(a Cipher, b matrix.Mat, outCols int) Cipher {
	return k.ServerMatmul(a, k.PrepareMatmul(a.Layout, b, outCols))
}

func (k Keys) Add(a, b Cipher) Cipher {
	k.Meter.begin("add", 0)
	out := bfv.NewCiphertext(k.ctx.Params, 1)
	k.eval.Add(a.ct, b.ct, out)
	k.Meter.finish("add", 0)
	k.Count.Add++
	return Cipher{a.Layout, out}
}

func (k Keys) Square(a Cipher) Cipher {
	deg2 := k.eval.MulNew(a.ct, a.ct)
	k.Count.MulCt++
	k.eval.Relinearize(deg2, deg2)
	return Cipher{a.Layout, deg2}
}

func (k Keys) Slots() int { return k.ctx.Slots() }

// Low-level operations for package attacks. A missing key makes Lattigo panic,
// which the caller records.

func (k Keys) RotateCols(c Cipher, offset int) Cipher {
	if offset == 0 {
		return c
	}
	k.Count.Rotate++
	k.Meter.begin("rotate", offset)
	out := k.eval.RotateColumnsNew(c.ct, offset)
	k.Meter.finish("rotate", offset)
	return Cipher{c.Layout, out}
}

func (k Keys) MulMask(c Cipher, mask []uint64) Cipher {
	k.Count.MulPt++
	k.Meter.begin("mul_pt", 0)
	out := k.eval.MulNew(c.ct, k.maskPt(mask))
	k.Meter.finish("mul_pt", 0)
	return Cipher{c.Layout, out}
}

func (k Keys) MulCipher(a, b Cipher) Cipher {
	k.Meter.begin("mul_ct", 0)
	deg2 := k.eval.MulNew(a.ct, b.ct)
	k.Meter.finish("mul_ct", 0)
	k.Count.MulCt++
	k.Meter.begin("relin", 0)
	k.eval.Relinearize(deg2, deg2)
	k.Meter.finish("relin", 0)
	return Cipher{a.Layout, deg2}
}

func (k Keys) Sub(a, b Cipher) Cipher {
	k.Count.Add++
	k.Meter.begin("sub", 0)
	out := k.eval.SubNew(a.ct, b.ct)
	k.Meter.finish("sub", 0)
	return Cipher{a.Layout, out}
}

// WithLayout re-labels a ciphertext's logical layout without touching data.
func (c Cipher) WithLayout(l Layout) Cipher { return Cipher{l, c.ct} }
