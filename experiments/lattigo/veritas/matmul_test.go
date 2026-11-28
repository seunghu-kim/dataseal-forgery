package veritas

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"

	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"veritas/vche/vche_2"

	"dsfgo/field"
	"dsfgo/matrix"
)

// TPE is the PE plaintext modulus: the largest prime t = 1 mod 2N below every PN14
// Q/P prime (54-bit). T58 (rejected by Lattigo, t > Q[0]) and T56 (exceeds q3..q5,
// where EncodeUintMul is invalid) are kept for diagnostics only.
const (
	T58 = 288230376155250689
	T56 = 72057594037370881
	TPE = 18014398507614209
)

func litT(t uint64) bfv.ParametersLiteral {
	lit := bfv.PN14QP438
	lit.T = t
	return lit
}

var f17 = field.New(65537)

func newRep(t *testing.T, g Geometry) *Rep {
	t.Helper()
	r, err := NewRepParams(bfv.PN14QP438, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CheckCapacity(r.LogicalSlots()); err != nil {
		t.Fatal(err)
	}
	r.KeyGen(g.Rotations(), nil)
	return r
}

func newPe(t *testing.T, tmod uint64, g Geometry) *Pe {
	t.Helper()
	p, err := NewPeParams(litT(tmod))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CheckCapacity(p.LogicalSlots()); err != nil {
		t.Fatal(err)
	}
	p.KeyGen(g.Rotations(), nil)
	return p
}

type runResult struct {
	in   Input
	prog Program
	out  Output
	ver  Verif
	res  Result
}

func runAll(s Scheme, g Geometry, a, b matrix.Mat) runResult {
	var r runResult
	r.prog = Prepare(s, g, b)
	r.in = Encrypt(s, g, a, nil)
	r.out = Server(s, r.in, r.prog)
	r.ver = Verifier(s, r.in, r.prog)
	r.res = Verify(s, Decrypt(s, r.out), r.ver)
	return r
}

func reduce17(m matrix.Mat) matrix.Mat {
	out := matrix.New(m.Rows(), m.Cols())
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			out.Set(i, j, m.At(i, j)%65537)
		}
	}
	return out
}

func copyTiles(x [][]any) [][]any {
	y := make([][]any, len(x))
	for i := range x {
		y[i] = append([]any(nil), x[i]...)
	}
	return y
}

func verifyWith(s Scheme, out [][]any, g Geometry, v Verif) Result {
	return Verify(s, Decrypt(s, Output{Geo: g, cts: out}), v)
}

// REP (lambda=64, PN14): single ciphertext, 2x2 tiles, a non-square tail, and an
// edge-filling tile (n=11) where the verifier's full-N rotation differs from the
// BFV half-row rotation outside the masked region.
func TestREPCorrectAndAccepted(t *testing.T) {
	cases := []struct{ n, inner, ell, block int }{{8, 8, 8, 8}, {16, 16, 16, 8}, {12, 10, 9, 8}, {11, 11, 11, 11}}
	for _, c := range cases {
		g := NewGeometry(c.n, c.inner, c.ell, c.block)
		r := newRep(t, g)
		a, b := vmat(f17, c.n, c.inner, 1), vmat(f17, c.inner, c.ell, 2)
		run := runAll(r, g, a, b)
		if !run.res.Accepted {
			t.Fatalf("REP %+v rejected: %v", c, run.res.Errors)
		}
		if !run.res.Out.Equal(matrix.Mul(f17, a, b)) {
			t.Fatalf("REP %+v wrong output", c)
		}
		t.Logf("REP %+v tiles in=%d out=%d ops=%+v accepted", c, run.in.NumTiles(), run.out.NumTiles(), run.prog.Ops)
	}
}

func TestPECorrectAndAccepted(t *testing.T) {
	for _, tm := range []uint64{TPE, 65537} {
		for _, c := range []struct{ n, block int }{{8, 8}, {16, 8}, {16, 16}} {
			g := NewGeometry(c.n, c.n, c.n, c.block)
			p := newPe(t, tm, g)
			a, b := vmat(f17, c.n, c.n, 1), vmat(f17, c.n, c.n, 2)
			run := runAll(p, g, a, b)
			if !run.res.Accepted {
				t.Fatalf("PE t=%d %+v rejected: %v", tm, c, run.res.Errors)
			}
			if !reduce17(run.res.Out).Equal(matrix.Mul(f17, a, b)) {
				t.Fatalf("PE t=%d %+v wrong output", tm, c)
			}
		}
	}
}

// Diagnostic: Lattigo refuses T58 on PN14 because t > Q[0].
func TestPET58RejectedByLattigoOnPN14(t *testing.T) {
	_, err := bfv.NewParametersFromLiteral(litT(T58))
	if err == nil {
		t.Fatalf("expected Lattigo to reject T58 on PN14")
	}
	t.Logf("T58 on PN14: %v", err)
}

// PN14 + TPE (54-bit): PE encryption/decryption roundtrip is exact.
func TestPET58DecryptRoundtrip(t *testing.T) {
	g := NewGeometry(8, 8, 8, 8)
	p := newPe(t, TPE, g)
	ok, err := pT58Params()
	if err != nil || !ok {
		t.Fatalf("TPE parameter checks failed: %v", err)
	}
	vals := make([]uint64, p.LogicalSlots())
	for i := range vals {
		vals[i] = uint64(i*7919+13) % TPE
	}
	vals[1] = TPE - 1
	ct, ver := p.encryptVec(vals, nil)
	got, derr := p.decodeVerify(p.decrypt(ct), ver)
	if derr != nil {
		t.Fatalf("TPE decode/verify rejected a fresh encryption: %v", derr)
	}
	for i := range vals {
		if got[i] != vals[i] {
			t.Fatalf("TPE roundtrip mismatch at %d: %d != %d", i, got[i], vals[i])
		}
	}
}

// pT58Params checks that TPE is prime, t = 1 mod 2N, below every Q/P prime, and maximal.
func pT58Params() (bool, error) {
	params, err := bfv.NewParametersFromLiteral(litT(TPE))
	if err != nil {
		return false, err
	}
	if err := CheckPlaintextModulus(params); err != nil {
		return false, err
	}
	m := uint64(2 * params.N())
	if TPE%m != 1 || !new(big.Int).SetUint64(TPE).ProbablyPrime(40) {
		return false, nil
	}
	minQP := params.Q()[0]
	for _, q := range append(append([]uint64{}, params.Q()...), params.P()...) {
		if q < minQP {
			minQP = q
		}
	}
	for t := TPE + m; t < minQP; t += m {
		if new(big.Int).SetUint64(t).ProbablyPrime(40) {
			return false, fmt.Errorf("larger valid modulus %d exists", t)
		}
	}
	return true, nil
}

// Diagnostic: with T56 the default EncodeUintMul path gives a wrong ct x pt
// product, so the adapter refuses such t.
func TestDefaultMulEncodingWithT56Diagnostic(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(litT(T56))
	if err != nil {
		t.Logf("T56 parameters rejected: %v", err)
		return
	}
	t.Logf("adapter guard: %v", CheckPlaintextModulus(params))
	n := params.N()
	a, b := make([]uint64, n), make([]uint64, n)
	for i := range a {
		a[i], b[i] = uint64(i%65536+1), uint64((7*i)%65536+1)
	}
	t56MulDiagnostic(t, params, "slot values 1..65536", a, b)
}

// Diagnostic: slot values themselves at or above q5 (in [q5, T56)).
func TestDefaultMulEncodingWithT56LargeSlotsDiagnostic(t *testing.T) {
	params, err := bfv.NewParametersFromLiteral(litT(T56))
	if err != nil {
		t.Logf("T56 parameters rejected: %v", err)
		return
	}
	q5 := uint64(0x3fffffffeb8001)
	span := T56 - q5
	n := params.N()
	a, b := make([]uint64, n), make([]uint64, n)
	for i := range a {
		a[i] = q5 + (uint64(i)*2654435761)%span
		b[i] = q5 + (uint64(i)*40503+12345)%span
	}
	t56MulDiagnostic(t, params, "slot values in [q5, T56)", a, b)
}

// t56MulDiagnostic reports how many R_t coefficients of the mask are >= q5 and
// whether the ct x pt product is correct.
func t56MulDiagnostic(t *testing.T, params bfv.Parameters, label string, a, b []uint64) {
	t.Helper()
	enc := bfv.NewEncoder(params)
	rt := bfv.NewPlaintextRingT(params)
	enc.EncodeUintRingT(b, rt)
	minQ := params.Q()[0]
	for _, q := range params.Q() {
		if q < minQ {
			minQ = q
		}
	}
	large := 0
	for _, c := range rt.Value.Coeffs[0] {
		if c >= minQ {
			large++
		}
	}
	sk, pk := bfv.NewKeyGenerator(params).GenKeyPair()
	n := params.N()
	pa := bfv.NewPlaintext(params)
	enc.EncodeUint(a, pa)
	pb := bfv.NewPlaintextMul(params)
	enc.EncodeUintMul(b, pb)
	ct := bfv.NewEvaluator(params, rlwe.EvaluationKey{}).MulNew(bfv.NewEncryptor(params, pk).EncryptNew(pa), pb)
	got := enc.DecodeUintNew(bfv.NewDecryptor(params, sk).DecryptNew(ct))
	wrong := 0
	for i := range got {
		want := new(big.Int).Mul(new(big.Int).SetUint64(a[i]), new(big.Int).SetUint64(b[i]))
		if got[i] != want.Mod(want, new(big.Int).SetUint64(T56)).Uint64() {
			wrong++
		}
	}
	t.Logf("T56 default EncodeUintMul [%s]: %d of %d R_t coefficients >= min q_i (%d); ct x pt product wrong in %d of %d slots", label, large, n, minQ, wrong, n)
}

// residualBudgetBits returns log2(Delta/2) - log2(max |e|); decryption is correct
// while it is positive.
func residualBudgetBits(params bfv.Parameters, sk *rlwe.SecretKey, ct *bfv.Ciphertext) float64 {
	enc := bfv.NewEncoder(params)
	pt := bfv.NewDecryptor(params, sk).DecryptNew(ct)
	vals := enc.DecodeUintNew(pt)
	ref := bfv.NewPlaintext(params)
	enc.EncodeUint(vals, ref)
	ringQ := params.RingQ()
	diff := ringQ.NewPoly()
	ringQ.Sub(pt.Value, ref.Value, diff)
	coeffs := make([]*big.Int, ringQ.N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	ringQ.PolyToBigintCenteredLvl(diff.Level(), diff, coeffs)
	maxE := new(big.Int)
	for _, c := range coeffs {
		if a := new(big.Int).Abs(c); a.Cmp(maxE) > 0 {
			maxE = a
		}
	}
	q := ringQ.ModulusBigint
	delta := new(big.Int).Quo(q, new(big.Int).SetUint64(params.T()))
	halfDelta, _ := new(big.Float).SetInt(new(big.Int).Rsh(delta, 1)).Float64()
	e, _ := new(big.Float).SetInt(maxE).Float64()
	if e < 1 {
		e = 1
	}
	return math.Log2(halfDelta) - math.Log2(e)
}

// Residual noise budget after the matmul, per PE component (n=16 here).
func TestPET58NoiseBudgetAfterMatmul(t *testing.T) {
	for _, tm := range []uint64{TPE, 65537} {
		g := NewGeometry(16, 16, 16, 16)
		p := newPe(t, tm, g)
		a, b := vmat(f17, 16, 16, 1), vmat(f17, 16, 16, 2)
		run := runAll(p, g, a, b)
		if !run.res.Accepted {
			t.Fatalf("t=%d rejected: %v", tm, run.res.Errors)
		}
		fresh := run.in.cts[0][0].(*vche_2.Ciphertext)
		out := run.out.cts[0][0].(*vche_2.Ciphertext)
		for i, c := range out.Ciphertexts {
			before := residualBudgetBits(p.Params.Parameters, p.sk.SecretKey, fresh.Ciphertexts[i])
			after := residualBudgetBits(p.Params.Parameters, p.sk.SecretKey, c)
			t.Logf("PE t=%d component %d: residual budget fresh %.1f bits, after matmul %.1f bits", tm, i, before, after)
			if after < 20 {
				t.Fatalf("PE t=%d component %d residual budget %.1f bits < 20", tm, i, after)
			}
		}
	}
	g := NewGeometry(8, 8, 8, 8)
	r := newRep(t, g)
	run := runAll(r, g, vmat(f17, 8, 8, 1), vmat(f17, 8, 8, 2))
	ct := run.out.cts[0][0].(*vche_1.Ciphertext)
	t.Logf("REP t=65537 residual budget after matmul %.1f bits", residualBudgetBits(r.Params.Parameters, r.sk.SecretKey, ct.Ciphertext))
}

// Diagnostic: T equal to PN14 q0 cannot work (Q mod t = 0); the test passes when
// the failure is observed.
func TestPETq0CollisionFailsDiagnostic(t *testing.T) {
	const tq0 = 72057594038321153
	lit := litT(tq0)
	if lit.Q[0] != tq0 {
		t.Fatalf("expected T to equal PN14 q0")
	}
	outcome := func() (o string) {
		defer func() {
			if r := recover(); r != nil {
				o = "panic: " + toString(r)
			}
		}()
		p, err := NewPeParams(lit)
		if err != nil {
			return "parameter error: " + err.Error()
		}
		g := NewGeometry(4, 4, 4, 4)
		p.KeyGen(g.Rotations(), nil)
		vals := make([]uint64, p.LogicalSlots())
		for i := range vals {
			vals[i] = uint64(i + 1)
		}
		ct, ver := p.encryptVec(vals, nil)
		got, derr := p.decodeVerify(p.decrypt(ct), ver)
		if derr != nil {
			return "verification rejected fresh encryption: " + derr.Error()
		}
		for i := range vals {
			if got[i] != vals[i] {
				return "wrong decryption"
			}
		}
		return "works"
	}()
	t.Logf("T=q0 outcome: %s", outcome)
	if outcome == "works" {
		t.Fatalf("T=q0 unexpectedly worked; plan_v2 §0.1 analysis would be wrong")
	}
}

func toString(v any) string {
	if e, ok := v.(error); ok {
		return e.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "non-string panic"
}

// Server view of a PlaintextMul: public Lattigo decoding (inverse NTT, batching).
func serverDecode(params bfv.Parameters, pt *bfv.PlaintextMul) []uint64 {
	return bfv.NewEncoder(params).DecodeUintNew(pt)
}

func randomNonzero(n int, seed uint64) []uint64 {
	v := make([]uint64, n)
	s := seed
	for i := range v {
		s = s*6364136223846793005 + 1442695040888963407
		v[i] = 1 + (s>>11)%65536
	}
	return v
}

// recoverS guesses the dummy set: positions of slot i whose value differs from the
// known public coefficient c.
func recoverS(vals []uint64, lambda, slot int, c uint64) map[int]bool {
	s := map[int]bool{}
	for j := 0; j < lambda; j++ {
		if vals[slot*lambda+j] != c {
			s[j] = true
		}
	}
	return s
}

func sameSet(a map[int]bool, b vche_1.DummySet) bool {
	n := 0
	for j, v := range b {
		if v {
			n++
			if !a[j] {
				return false
			}
		}
	}
	return n == len(a)
}

// With an authenticated (tagged) mask, the server recovers REP's secret dummy set S.
func TestM1MaskLeaksREPDummySet(t *testing.T) {
	g := NewGeometry(8, 8, 8, 8)
	r := newRep(t, g)
	coeffs := randomNonzero(r.LogicalSlots(), 3)
	m1 := r.encoder.EncodeUintMulNew(coeffs, vche.GetRandomTags(r.LogicalSlots()))
	vals := serverDecode(r.Params.Parameters, m1.PlaintextMul)
	lam := r.Params.NumReplications
	for slot := 0; slot < 4; slot++ {
		if got := recoverS(vals, lam, slot, coeffs[slot]); !sameSet(got, r.sk.S) {
			t.Fatalf("M1: expected S recovery at slot %d (|guess|=%d)", slot, len(got))
		}
	}
	t.Logf("M1 REP: server recovered the %d-element dummy set S from the plaintext mask", len(r.sk.S))
}

// Two authenticated term masks sharing tags reveal PE's alpha.
func TestM1MaskLeaksPEAlpha(t *testing.T) {
	g := NewGeometry(8, 8, 8, 8)
	p := newPe(t, 65537, g)
	tags := vche.GetRandomTags(p.LogicalSlots())
	ca, cb := randomNonzero(p.LogicalSlots(), 5), randomNonzero(p.LogicalSlots(), 6)
	slot := 0
	for ca[slot] == cb[slot] {
		slot++
	}
	ma, mb := p.encoder.EncodeUintMulNew(ca, tags), p.encoder.EncodeUintMulNew(cb, tags)
	ya := serverDecode(p.Params.Parameters, ma.Plaintexts[1])[slot]
	yb := serverDecode(p.Params.Parameters, mb.Plaintexts[1])[slot]
	tt := p.Params.T()
	num := (cb[slot] + tt - ca[slot]) % tt
	den := (ya + tt - yb) % tt
	alpha := new(big.Int).Mul(new(big.Int).SetUint64(num), new(big.Int).ModInverse(new(big.Int).SetUint64(den), new(big.Int).SetUint64(tt)))
	alpha.Mod(alpha, new(big.Int).SetUint64(tt))
	if alpha.Uint64() != p.sk.Alpha[0] {
		t.Fatalf("M1: expected alpha recovery")
	}
	t.Logf("M1 PE: server recovered alpha from two shared-tag plaintext masks")
}

func polyBytes(t *testing.T, p *ring.Poly) []byte {
	t.Helper()
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Public masks are byte-identical across sessions with different keys, and the
// recovery procedures learn nothing.
func TestM4MaskIsSecretFree(t *testing.T) {
	g := NewGeometry(8, 8, 8, 8)
	r1, r2 := newRep(t, g), newRep(t, g)
	coeffs := randomNonzero(r1.LogicalSlots(), 7)
	s1, v1 := PublicMaskREP(r1.Params, r1.pubEnc, coeffs)
	s2, v2 := PublicMaskREP(r2.Params, r2.pubEnc, coeffs)
	if !bytes.Equal(polyBytes(t, s1.Value), polyBytes(t, s2.Value)) || !bytes.Equal(polyBytes(t, v1.Poly), polyBytes(t, v2.Poly)) {
		t.Fatalf("M4 REP masks differ across key sessions")
	}
	vals := serverDecode(r1.Params.Parameters, s1.PlaintextMul)
	for slot := 0; slot < 4; slot++ {
		if got := recoverS(vals, r1.Params.NumReplications, slot, coeffs[slot]); len(got) != 0 || sameSet(got, r1.sk.S) {
			t.Fatalf("M4 REP: recovery procedure distinguished positions at slot %d", slot)
		}
	}
	for _, tm := range []uint64{TPE, 65537} {
		p1, p2 := newPe(t, tm, g), newPe(t, tm, g)
		m1, w1 := PublicMaskPE(p1.Params, p1.pubEnc, coeffs)
		m2, w2 := PublicMaskPE(p2.Params, p2.pubEnc, coeffs)
		if m1.Len() != 1 {
			t.Fatalf("M4 PE mask must have a single public component, got %d", m1.Len())
		}
		if !bytes.Equal(polyBytes(t, m1.Plaintexts[0].Value), polyBytes(t, m2.Plaintexts[0].Value)) || !bytes.Equal(polyBytes(t, w1.Poly), polyBytes(t, w2.Poly)) {
			t.Fatalf("M4 PE t=%d masks differ across key sessions", tm)
		}
	}
	t.Logf("M4: masks identical across keys; REP recovery finds no dummy positions; PE mask has no y component (alpha not computable)")
}

func TestM4ForgeryWrongPublicOperandRejected(t *testing.T) {
	g := NewGeometry(8, 8, 8, 8)
	a, b := vmat(f17, 8, 8, 1), vmat(f17, 8, 8, 2)
	bBad := vmat(f17, 8, 8, 2)
	bBad.Set(3, 5, (bBad.At(3, 5)+1)%65537)
	schemes := []Scheme{newRep(t, g), newPe(t, TPE, g), newPe(t, 65537, g)}
	for _, s := range schemes {
		good, bad := Prepare(s, g, b), Prepare(s, g, bBad)
		in := Encrypt(s, g, a, nil)
		res := Verify(s, Decrypt(s, Server(s, in, bad)), Verifier(s, in, good))
		if res.Accepted {
			t.Fatalf("%s accepted evaluation with a substituted public operand", s.Name())
		}
		t.Logf("%s: substituted b' rejected (%s)", s.Name(), res.Errors[0])
	}
}

// REP: a mask differing from b on a single replica position is rejected, whether
// that position is a dummy or a replica.
func TestM4ForgeryReplicaWiseConstantREP(t *testing.T) {
	g := NewGeometry(4, 4, 4, 4)
	r := newRep(t, g)
	a, b := vmat(f17, 4, 4, 1), vmat(f17, 4, 4, 2)
	in := Encrypt(r, g, a, nil)
	good := Prepare(r, g, b)
	ver := Verifier(r, in, good)
	lam := r.Params.NumReplications
	dummy, replica := -1, -1
	for j := 0; j < lam; j++ {
		if r.sk.S[j] && dummy < 0 {
			dummy = j
		}
		if !r.sk.S[j] && replica < 0 {
			replica = j
		}
	}
	for _, j0 := range []int{dummy, replica} {
		bad := good
		bad.blocks = [][][]maskTerm{{append([]maskTerm(nil), good.blocks[0][0]...)}}
		term := bad.blocks[0][0][0] // delta 0 term
		v := serverDecode(r.Params.Parameters, term.srv.(*vche_1.PlaintextMul).PlaintextMul)
		v[0*lam+j0] = (v[0*lam+j0] + 1) % 65537
		pt := vche_1.NewPlaintextMul(r.Params)
		r.pubEnc.EncodeUintMul(v, pt.PlaintextMul)
		bad.blocks[0][0][0] = maskTerm{term.delta, pt, term.ver}
		if res := Verify(r, Decrypt(r, Server(r, in, bad)), ver); res.Accepted {
			t.Fatalf("REP accepted replica-wise mask change at position %d (dummy=%v)", j0, r.sk.S[j0])
		}
	}
}

// PE: multiplying the two ciphertext components by different public constants is rejected.
func TestM4ForgeryComponentWiseConstantPE(t *testing.T) {
	for _, tm := range []uint64{TPE, 65537} {
		g := NewGeometry(4, 4, 4, 4)
		p := newPe(t, tm, g)
		a := vmat(f17, 4, 4, 1)
		id := matrix.New(4, 4)
		for i := 0; i < 4; i++ {
			id.Set(i, i, uint64(3+i))
		}
		in := Encrypt(p, g, a, nil)
		prog := Prepare(p, g, id) // diagonal B: only the delta-0 term
		if len(prog.blocks[0][0]) != 1 {
			t.Fatalf("expected a single term")
		}
		ver := Verifier(p, in, prog)
		coeffs := make([]uint64, p.LogicalSlots())
		coeffs2 := make([]uint64, p.LogicalSlots())
		for r := 0; r < 4; r++ { // delta-0 mask of Prepare: B[c][c] on every row
			for c := 0; c < 4; c++ {
				coeffs[g.Dim*r+c] = id.At(c, c)
				coeffs2[g.Dim*r+c] = id.At(c, c)
			}
		}
		coeffs2[0] = 99 // different constant on component 1, slot 0
		m0, _ := PublicMaskPE(p.Params, p.pubEnc, coeffs)
		m1, _ := PublicMaskPE(p.Params, p.pubEnc, coeffs2)
		ev := bfv.NewEvaluator(p.Params.Parameters, rlwe.EvaluationKey{})
		ct := in.cts[0][0].(*vche_2.Ciphertext)
		forged := &vche_2.Ciphertext{Ciphertexts: []*bfv.Ciphertext{ev.MulNew(ct.Ciphertexts[0], m0.Plaintexts[0]), ev.MulNew(ct.Ciphertexts[1], m1.Plaintexts[0])}}
		res := verifyWith(p, [][]any{{forged}}, g, ver)
		if res.Accepted {
			t.Fatalf("PE t=%d accepted component-wise different constants", tm)
		}
		honest := &vche_2.Ciphertext{Ciphertexts: []*bfv.Ciphertext{ev.MulNew(ct.Ciphertexts[0], m0.Plaintexts[0]), ev.MulNew(ct.Ciphertexts[1], m0.Plaintexts[0])}}
		if res := verifyWith(p, [][]any{{honest}}, g, ver); !res.Accepted {
			t.Fatalf("PE t=%d control (same constant) rejected: %v", tm, res.Errors)
		}
	}
}

func encryptPublicVec(params bfv.Parameters, enc bfv.Encoder, pk *rlwe.PublicKey, v []uint64) *bfv.Ciphertext {
	pt := bfv.NewPlaintext(params)
	enc.EncodeUint(v, pt)
	return bfv.NewEncryptor(params, pk).EncryptNew(pt)
}

type tamperCase struct {
	name string
	mut  func(out [][]any) [][]any
}

func checkTiledTamper(t *testing.T, s Scheme, s2 Scheme, g Geometry, a, b matrix.Mat, coeffTamper func(ct any) any) {
	run := runAll(s, g, a, b)
	if !run.res.Accepted {
		t.Fatalf("%s honest tiled run rejected: %v", s.Name(), run.res.Errors)
	}
	other := runAll(s2, g, a, b)
	cases := []tamperCase{
		{"output tile coefficient", func(o [][]any) [][]any { o[0][1] = coeffTamper(o[0][1]); return o }},
		{"tile position swap", func(o [][]any) [][]any { o[0][0], o[1][1] = o[1][1], o[0][0]; return o }},
		{"other-session tile", func(o [][]any) [][]any { o[1][0] = other.out.cts[1][0]; return o }},
	}
	for _, c := range cases {
		res := verifyWith(s, c.mut(copyTiles(run.out.cts)), g, run.ver)
		if res.Accepted {
			t.Fatalf("%s: tamper %q accepted", s.Name(), c.name)
		}
		t.Logf("%s: tamper %q rejected (%d tile errors)", s.Name(), c.name, len(res.Errors))
	}
	swapped := Input{Geo: g, cts: copyTiles(run.in.cts), vers: run.in.vers}
	swapped.cts[0][0], swapped.cts[1][1] = swapped.cts[1][1], swapped.cts[0][0]
	res := Verify(s, Decrypt(s, Server(s, swapped, run.prog)), run.ver)
	if res.Accepted {
		t.Fatalf("%s: input tile swap accepted", s.Name())
	}
	t.Logf("%s: tamper %q rejected (%d tile errors)", s.Name(), "input tile swap", len(res.Errors))
}

func TestTiledTamperREP(t *testing.T) {
	g := NewGeometry(16, 16, 16, 8)
	r, r2 := newRep(t, g), newRep(t, g)
	lam := r.Params.NumReplications
	tamper := func(ct any) any {
		c := r.evaluator.CopyNew(ct.(*vche_1.Ciphertext)).(*vche_1.Ciphertext) // keep the honest tile intact
		v := make([]uint64, r.Params.N())
		for j := 0; j < lam; j++ {
			v[0*lam+j] = 5 // consistent delta on every replica of logical slot 0
		}
		d := encryptPublicVec(r.Params.Parameters, r.pubEnc, r.pk.PublicKey, v)
		bfv.NewEvaluator(r.Params.Parameters, rlwe.EvaluationKey{}).Add(c.Ciphertext, d, c.Ciphertext)
		return c
	}
	checkTiledTamper(t, r, r2, g, vmat(f17, 16, 16, 1), vmat(f17, 16, 16, 2), tamper)
}

func TestTiledTamperPE(t *testing.T) {
	for _, tm := range []uint64{TPE, 65537} {
		g := NewGeometry(16, 16, 16, 8)
		p, p2 := newPe(t, tm, g), newPe(t, tm, g)
		tamper := func(ct any) any {
			c := ct.(*vche_2.Ciphertext)
			v := make([]uint64, p.Params.N())
			v[0] = 5
			d := encryptPublicVec(p.Params.Parameters, p.pubEnc, p.pk, v)
			parts := append([]*bfv.Ciphertext(nil), c.Ciphertexts...)
			parts[0] = bfv.NewEvaluator(p.Params.Parameters, rlwe.EvaluationKey{}).AddNew(parts[0], d)
			return &vche_2.Ciphertext{Ciphertexts: parts}
		}
		checkTiledTamper(t, p, p2, g, vmat(f17, 16, 16, 1), vmat(f17, 16, 16, 2), tamper)
	}
}
