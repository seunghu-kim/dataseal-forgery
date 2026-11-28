// Package dataseal implements DataSeal encoding and verification.
// Matrix multiplication uses the row order [data; weighted; golden].
package dataseal

import (
	"dsfgo/field"
	"dsfgo/matrix"
)

// MatmulVerifier selects the original checks, the corrected check, or the variant
// of DataSeal's Appendix A.
type MatmulVerifier int

const (
	Original MatmulVerifier = iota
	Corrected
	Appendix
)

func (v MatmulVerifier) String() string {
	switch v {
	case Original:
		return "dataseal_original"
	case Corrected:
		return "dataseal_strengthened"
	case Appendix:
		return "dataseal_appendix"
	}
	return "unknown"
}

type VerifyResult struct {
	ShapeOK bool
	Checks  map[string]bool
}

func (r VerifyResult) Accepted() bool {
	if !r.ShapeOK {
		return false
	}
	for _, ok := range r.Checks {
		if !ok {
			return false
		}
	}
	return true
}

type MatmulKey struct {
	K     []uint64
	Alpha uint64
}

type MatmulClient struct {
	Key         MatmulKey
	N, D, Ell   int
	W, G, U0, Z []uint64
}

type MatmulEncoding struct {
	Client MatmulClient
	AStar  matrix.Mat
	B      matrix.Mat
}

// MatmulInputChecksum returns w = A^T k and g = alpha*w; they do not depend on
// the public matrix B.
func MatmulInputChecksum(f field.Field, a matrix.Mat, key MatmulKey) (w, g []uint64) {
	w = matrix.MatTVec(f, a, key.K)
	g = scale(f, key.Alpha, w)
	return w, g
}

// MatmulExpected returns u0 = B^T w and z = B^T g.
func MatmulExpected(f field.Field, b matrix.Mat, w, g []uint64) (u0, z []uint64) {
	u0 = matrix.MatTVec(f, b, w)
	z = matrix.MatTVec(f, b, g)
	return u0, z
}

// MatmulEncode builds A* = [A; w; g] and the client's expected values u0 and z.
func MatmulEncode(f field.Field, a, b matrix.Mat, key MatmulKey) MatmulEncoding {
	if len(key.K) != a.Rows() {
		panic("matmul key length must equal row count")
	}
	if a.Cols() != b.Rows() {
		panic("matmul shape mismatch")
	}
	var e MatmulEncoding
	e.Client.Key = key
	e.Client.N, e.Client.D, e.Client.Ell = a.Rows(), a.Cols(), b.Cols()
	e.Client.W, e.Client.G = MatmulInputChecksum(f, a, key)
	e.Client.U0, e.Client.Z = MatmulExpected(f, b, e.Client.W, e.Client.G)
	e.AStar = a.AppendRows(e.Client.W, e.Client.G)
	e.B = b
	return e
}

func MatmulEval(f field.Field, e MatmulEncoding) matrix.Mat { return matrix.Mul(f, e.AStar, e.B) }

// MatmulVerify checks C^T k = u on [C; u; v]. Original checks: also v = z.
// Corrected check: also u = u0 and v = z. Appendix A variant: v = alpha*u.
func MatmulVerify(f field.Field, cs MatmulClient, cStar matrix.Mat, mode MatmulVerifier) VerifyResult {
	r := VerifyResult{Checks: map[string]bool{}}
	r.ShapeOK = cStar.Rows() == cs.N+2 && cStar.Cols() == cs.Ell
	if !r.ShapeOK {
		return r
	}
	c := cStar.TopRows(cs.N)
	u := cStar.Row(cs.N)
	v := cStar.Row(cs.N + 1)
	r.Checks["weighted_checksum"] = eq(matrix.MatTVec(f, c, cs.Key.K), u)
	switch mode {
	case Original:
		r.Checks["golden_output"] = eq(v, cs.Z)
	case Corrected:
		r.Checks["expected_checksum"] = eq(u, cs.U0)
		r.Checks["golden_output"] = eq(v, cs.Z)
	case Appendix:
		r.Checks["scaled_checksum"] = eq(v, scale(f, cs.Key.Alpha, u))
	}
	return r
}

type AddClient struct {
	K    []uint64
	N, D int
	Z    []uint64
}

type AddEncoding struct {
	Client       AddClient
	AStar, BStar matrix.Mat
}

// AddEncode appends A^T k to A and B^T k to B; the expected value z is their sum.
func AddEncode(f field.Field, a, b matrix.Mat, k []uint64) AddEncoding {
	if a.Rows() != b.Rows() || a.Cols() != b.Cols() {
		panic("addition shape mismatch")
	}
	if len(k) != a.Rows() {
		panic("addition key length mismatch")
	}
	var e AddEncoding
	e.Client.K = k
	e.Client.N, e.Client.D = a.Rows(), a.Cols()
	wa := matrix.MatTVec(f, a, k)
	wb := matrix.MatTVec(f, b, k)
	e.Client.Z = addv(f, wa, wb)
	e.AStar = a.AppendRows(wa)
	e.BStar = b.AppendRows(wb)
	return e
}

func AddEval(f field.Field, e AddEncoding) matrix.Mat { return matrix.Add(f, e.AStar, e.BStar) }

func AddVerify(f field.Field, cs AddClient, cStar matrix.Mat) VerifyResult {
	r := VerifyResult{Checks: map[string]bool{}}
	r.ShapeOK = cStar.Rows() == cs.N+1 && cStar.Cols() == cs.D
	if !r.ShapeOK {
		return r
	}
	c := cStar.TopRows(cs.N)
	u := cStar.Row(cs.N)
	r.Checks["expected_checksum"] = eq(u, cs.Z)
	r.Checks["weighted_checksum"] = eq(matrix.MatTVec(f, c, cs.K), u)
	return r
}

type SquareClient struct {
	Eta  []uint64
	N, D int
	Z    []uint64
}

type SquareEncoding struct {
	Client SquareClient
	AStar  matrix.Mat
}

// SquareEncode appends t_j = eta_j * prod_i a_ij (corrected Algorithm 6) and
// records z_j = t_j^2.
func SquareEncode(f field.Field, a matrix.Mat, eta []uint64) SquareEncoding {
	if len(eta) != a.Cols() {
		panic("square key length mismatch")
	}
	var e SquareEncoding
	e.Client.Eta = eta
	e.Client.N, e.Client.D = a.Rows(), a.Cols()
	prod := matrix.ColumnProducts(f, a)
	t := make([]uint64, e.Client.D)
	e.Client.Z = make([]uint64, e.Client.D)
	for j := 0; j < e.Client.D; j++ {
		t[j] = f.Mul(eta[j], prod[j])
		e.Client.Z[j] = f.Mul(t[j], t[j])
	}
	e.AStar = a.AppendRows(t)
	return e
}

func SquareEval(f field.Field, e SquareEncoding) matrix.Mat { return matrix.Square(f, e.AStar) }

// SquareVerify checks t = z and t_j = eta_j^2 * prod_i c_ij on [C; t].
func SquareVerify(f field.Field, cs SquareClient, cStar matrix.Mat) VerifyResult {
	r := VerifyResult{Checks: map[string]bool{}}
	r.ShapeOK = cStar.Rows() == cs.N+1 && cStar.Cols() == cs.D
	if !r.ShapeOK {
		return r
	}
	c := cStar.TopRows(cs.N)
	t := cStar.Row(cs.N)
	prod := matrix.ColumnProducts(f, c)
	productOK := true
	for j := 0; j < cs.D; j++ {
		e2 := f.Mul(cs.Eta[j], cs.Eta[j])
		if t[j] != f.Mul(e2, prod[j]) {
			productOK = false
		}
	}
	r.Checks["expected_checksum"] = eq(t, cs.Z)
	r.Checks["output_product"] = productOK
	return r
}

func scale(f field.Field, c uint64, a []uint64) []uint64 {
	r := make([]uint64, len(a))
	for i := range a {
		r[i] = f.Mul(c, a[i])
	}
	return r
}

func addv(f field.Field, a, b []uint64) []uint64 {
	r := make([]uint64, len(a))
	for i := range a {
		r[i] = f.Add(a[i], b[i])
	}
	return r
}

func eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
