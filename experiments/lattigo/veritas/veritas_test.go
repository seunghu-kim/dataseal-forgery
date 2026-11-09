package veritas

import (
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"

	"dsfgo/field"
)

var f = field.New(65537)

func logical(n int, seed uint64) []uint64 {
	v := make([]uint64, n)
	s := seed
	for i := range v {
		s = s*6364136223846793005 + 1442695040888963407
		v[i] = (s >> 11) % 65537
	}
	return v
}

func eq(a, b []uint64, n int) bool {
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// REP at NumReplications=4, PN13: matched elementwise addition and squaring,
// verified by the official REP authenticator.
func TestRepMatchedAddSquare(t *testing.T) {
	r := NewRep(bfv.PN13QP218, 4)
	n := 8
	a := logical(n, 1)
	b := logical(n, 2)
	out, ok := r.Add(a, b)
	if !ok {
		t.Fatal("REP add rejected honest")
	}
	want := make([]uint64, n)
	for i := 0; i < n; i++ {
		want[i] = f.Add(a[i], b[i])
	}
	if !eq(out, want, n) {
		t.Fatal("REP add wrong result")
	}
	sq, ok := r.Square(a)
	if !ok {
		t.Fatal("REP square rejected honest")
	}
	for i := 0; i < n; i++ {
		want[i] = f.Mul(a[i], a[i])
	}
	if !eq(sq, want, n) {
		t.Fatal("REP square wrong result")
	}
}

func TestPeMatchedAddSquare(t *testing.T) {
	p := NewPe(bfv.PN13QP218)
	n := 8
	a := logical(n, 3)
	b := logical(n, 4)
	out, ok := p.Add(a, b)
	if !ok {
		t.Fatal("PE add rejected honest")
	}
	want := make([]uint64, n)
	for i := 0; i < n; i++ {
		want[i] = f.Add(a[i], b[i])
	}
	if !eq(out, want, n) {
		t.Fatal("PE add wrong result")
	}
	sq, ok := p.Square(a)
	if !ok {
		t.Fatal("PE square rejected honest")
	}
	for i := 0; i < n; i++ {
		want[i] = f.Mul(a[i], a[i])
	}
	if !eq(sq, want, n) {
		t.Fatal("PE square wrong result")
	}
}
