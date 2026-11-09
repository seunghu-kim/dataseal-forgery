package matrix

import "dsfgo/field"

// Mat is a dense row-major matrix over F_p, matching src/matrix.cpp.
type Mat struct {
	rows, cols int
	a          []uint64
}

func New(rows, cols int) Mat { return Mat{rows, cols, make([]uint64, rows*cols)} }

func FromInts(f field.Field, rows [][]int64) Mat {
	r := len(rows)
	c := 0
	if r > 0 {
		c = len(rows[0])
	}
	m := New(r, c)
	for i, row := range rows {
		if len(row) != c {
			panic("ragged matrix literal")
		}
		for j, x := range row {
			m.Set(i, j, f.FromInt(x))
		}
	}
	return m
}

func (m Mat) Rows() int { return m.rows }
func (m Mat) Cols() int { return m.cols }

func (m Mat) At(i, j int) uint64  { return m.a[i*m.cols+j] }
func (m *Mat) Set(i, j int, v uint64) { m.a[i*m.cols+j] = v }

func (m Mat) Row(i int) []uint64 {
	out := make([]uint64, m.cols)
	copy(out, m.a[i*m.cols:(i+1)*m.cols])
	return out
}

func (m Mat) Col(j int) []uint64 {
	out := make([]uint64, m.rows)
	for i := 0; i < m.rows; i++ {
		out[i] = m.At(i, j)
	}
	return out
}

func (m *Mat) SetRow(i int, v []uint64) {
	if len(v) != m.cols {
		panic("set row shape mismatch")
	}
	copy(m.a[i*m.cols:(i+1)*m.cols], v)
}

func (m Mat) TopRows(k int) Mat {
	out := New(k, m.cols)
	copy(out.a, m.a[:k*m.cols])
	return out
}

func (m Mat) AppendRows(extra ...[]uint64) Mat {
	out := New(m.rows+len(extra), m.cols)
	copy(out.a, m.a)
	for k, v := range extra {
		out.SetRow(m.rows+k, v)
	}
	return out
}

func (m Mat) Equal(o Mat) bool {
	if m.rows != o.rows || m.cols != o.cols {
		return false
	}
	for i := range m.a {
		if m.a[i] != o.a[i] {
			return false
		}
	}
	return true
}

func Add(f field.Field, a, b Mat) Mat {
	requireShape(a, b)
	r := New(a.rows, a.cols)
	for i := range a.a {
		r.a[i] = f.Add(a.a[i], b.a[i])
	}
	return r
}

func Mul(f field.Field, a, b Mat) Mat {
	if a.cols != b.rows {
		panic("mat mul shape mismatch")
	}
	r := New(a.rows, b.cols)
	for i := 0; i < a.rows; i++ {
		for k := 0; k < a.cols; k++ {
			aik := a.At(i, k)
			if aik == 0 {
				continue
			}
			for j := 0; j < b.cols; j++ {
				r.Set(i, j, f.Add(r.At(i, j), f.Mul(aik, b.At(k, j))))
			}
		}
	}
	return r
}

func Scale(f field.Field, c uint64, a Mat) Mat {
	r := New(a.rows, a.cols)
	for i := range a.a {
		r.a[i] = f.Mul(c, a.a[i])
	}
	return r
}

func Hadamard(f field.Field, a, b Mat) Mat {
	requireShape(a, b)
	r := New(a.rows, a.cols)
	for i := range a.a {
		r.a[i] = f.Mul(a.a[i], b.a[i])
	}
	return r
}

func Square(f field.Field, a Mat) Mat { return Hadamard(f, a, a) }

// MatTVec computes A^T x (length cols), used for column checksums.
func MatTVec(f field.Field, a Mat, x []uint64) []uint64 {
	if len(x) != a.rows {
		panic("matTvec shape mismatch")
	}
	r := make([]uint64, a.cols)
	for i := 0; i < a.rows; i++ {
		for j := 0; j < a.cols; j++ {
			r[j] = f.Add(r[j], f.Mul(a.At(i, j), x[i]))
		}
	}
	return r
}

func ColumnProducts(f field.Field, a Mat) []uint64 {
	r := make([]uint64, a.cols)
	for j := range r {
		r[j] = 1 % f.P()
	}
	for i := 0; i < a.rows; i++ {
		for j := 0; j < a.cols; j++ {
			r[j] = f.Mul(r[j], a.At(i, j))
		}
	}
	return r
}

func Rank(f field.Field, src Mat) int {
	a := New(src.rows, src.cols)
	copy(a.a, src.a)
	r := 0
	for c := 0; c < a.cols && r < a.rows; c++ {
		piv := r
		for piv < a.rows && a.At(piv, c) == 0 {
			piv++
		}
		if piv == a.rows {
			continue
		}
		if piv != r {
			for j := 0; j < a.cols; j++ {
				t := a.At(piv, j)
				a.Set(piv, j, a.At(r, j))
				a.Set(r, j, t)
			}
		}
		iv := f.Inv(a.At(r, c))
		for i := r + 1; i < a.rows; i++ {
			mlt := f.Mul(a.At(i, c), iv)
			if mlt == 0 {
				continue
			}
			for j := c; j < a.cols; j++ {
				a.Set(i, j, f.Sub(a.At(i, j), f.Mul(mlt, a.At(r, j))))
			}
		}
		r++
	}
	return r
}

func IsZero(a Mat) bool {
	for _, x := range a.a {
		if x != 0 {
			return false
		}
	}
	return true
}

func requireShape(a, b Mat) {
	if a.rows != b.rows || a.cols != b.cols {
		panic("elementwise shape mismatch")
	}
}
