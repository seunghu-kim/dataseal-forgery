// Package sketch ports the private-sketch linear repair and its approved
// program chain from src/sketch.cpp and src/sketch_program.cpp.
package sketch

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"dsfgo/field"
	"dsfgo/matrix"
)

// RowsFor returns the smallest r with q_auth * p^-r <= 2^-lambda, using exact
// integer comparison (matches sketch_rows_for).
func RowsFor(p uint64, lambda uint, qAuth uint64) int {
	target := new(big.Int).Lsh(new(big.Int).SetUint64(qAuth), lambda)
	acc := big.NewInt(1)
	bp := new(big.Int).SetUint64(p)
	r := 0
	for acc.Cmp(target) < 0 {
		acc.Mul(acc, bp)
		r++
	}
	return r
}

// UniformElem draws a uniform F_p element from the OS CSPRNG via rejection.
func UniformElem(f field.Field) uint64 {
	p := f.P()
	limit := (^uint64(0) / p) * p
	var buf [8]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			panic(err)
		}
		x := binary.LittleEndian.Uint64(buf[:])
		if x < limit {
			return x % p
		}
	}
}

func RandomMat(f field.Field, rows, cols int) matrix.Mat {
	m := matrix.New(rows, cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			m.Set(i, j, UniformElem(f))
		}
	}
	return m
}

type Registration struct {
	Rows, Cols int
	W          matrix.Mat // K * A_tau
}

// Client holds the private sketch key K and registered sketches; never sent to
// the server.
type Client struct {
	K    matrix.Mat // r x n
	Regs map[string]Registration
}

// Server holds only the registered input matrices (data), as plaintext here;
// the HE layer (G2) encrypts them.
type Server struct {
	Inputs map[string]matrix.Mat
}

func Keygen(f field.Field, r, n int) Client {
	return Client{K: RandomMat(f, r, n), Regs: map[string]Registration{}}
}

func NewServer() Server { return Server{Inputs: map[string]matrix.Mat{}} }

func Register(f field.Field, cs *Client, sv *Server, label string, a matrix.Mat) {
	if a.Rows() != cs.K.Cols() {
		panic("registered input must have n rows")
	}
	if _, ok := cs.Regs[label]; ok {
		panic("label already registered")
	}
	cs.Regs[label] = Registration{a.Rows(), a.Cols(), matrix.Mul(f, cs.K, a)}
	sv.Inputs[label] = a
}

// --- Program chain ---

type StepKind int

const (
	Input StepKind = iota
	MulRight
	AddInput
	AddConst
)

type Step struct {
	Kind  StepKind
	Label string
	Mat   matrix.Mat // operand for MulRight/AddConst
}

type Program []Step

func (p Program) valid() {
	if len(p) == 0 || p[0].Kind != Input {
		panic("program must start with Input")
	}
}

// EvalPlain evaluates on plaintext inputs (reference).
func (p Program) EvalPlain(f field.Field, inputs map[string]matrix.Mat) matrix.Mat {
	p.valid()
	acc := inputs[p[0].Label]
	for _, s := range p[1:] {
		switch s.Kind {
		case Input:
			panic("Input may only appear first")
		case MulRight:
			acc = matrix.Mul(f, acc, s.Mat)
		case AddInput:
			acc = matrix.Add(f, acc, inputs[s.Label])
		case AddConst:
			acc = matrix.Add(f, acc, s.Mat)
		}
	}
	return acc
}

func Eval(f field.Field, sv Server, p Program) matrix.Mat { return p.EvalPlain(f, sv.Inputs) }

// Prepare computes the expected sketch T_P over the approved public operands.
func Prepare(f field.Field, cs Client, p Program) matrix.Mat {
	p.valid()
	reg, ok := cs.Regs[p[0].Label]
	if !ok {
		panic("unknown input label")
	}
	acc := reg.W
	for _, s := range p[1:] {
		switch s.Kind {
		case MulRight:
			acc = matrix.Mul(f, acc, s.Mat)
		case AddInput:
			r, ok := cs.Regs[s.Label]
			if !ok {
				panic("unknown input label")
			}
			acc = matrix.Add(f, acc, r.W)
		case AddConst:
			acc = matrix.Add(f, acc, matrix.Mul(f, cs.K, s.Mat))
		case Input:
			panic("Input may only appear first")
		}
	}
	return acc
}

// Verify is the verified-decryption check K Y' == T_P.
func Verify(f field.Field, cs Client, expected, y matrix.Mat) bool {
	if y.Rows() != cs.K.Cols() || y.Cols() != expected.Cols() {
		return false
	}
	return matrix.Mul(f, cs.K, y).Equal(expected)
}
