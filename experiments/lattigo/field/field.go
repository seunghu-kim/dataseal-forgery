// Package field implements exact arithmetic in F_p (p prime, p < 2^62); the
// experiments use p = 65537.
package field

import "math/bits"

type Field struct{ p uint64 }

func New(p uint64) Field {
	if p < 2 || p >= (1<<62) || !IsPrime(p) {
		panic("modulus must be a prime below 2^62")
	}
	return Field{p}
}

func (f Field) P() uint64 { return f.p }

// mulmod returns (a*b) mod m via a 128-bit product to avoid 64-bit overflow.
func mulmod(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi%m, lo, m)
	return rem
}

func powmod(a, e, m uint64) uint64 {
	r := uint64(1) % m
	a %= m
	for e > 0 {
		if e&1 == 1 {
			r = mulmod(r, a, m)
		}
		a = mulmod(a, a, m)
		e >>= 1
	}
	return r
}

// IsPrime is a deterministic Miller-Rabin test for all 64-bit integers.
func IsPrime(n uint64) bool {
	if n < 2 {
		return false
	}
	for _, q := range []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		if n%q == 0 {
			return n == q
		}
	}
	d := n - 1
	s := 0
	for d&1 == 0 {
		d >>= 1
		s++
	}
	for _, a := range []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		x := powmod(a, d, n)
		if x == 1 || x == n-1 {
			continue
		}
		composite := true
		for r := 1; r < s; r++ {
			x = mulmod(x, x, n)
			if x == n-1 {
				composite = false
				break
			}
		}
		if composite {
			return false
		}
	}
	return true
}

func (f Field) FromInt(x int64) uint64 {
	m := int64(f.p)
	r := x % m
	if r < 0 {
		r += m
	}
	return uint64(r)
}

func (f Field) FromU64(x uint64) uint64 { return x % f.p }

// Centered returns the signed representative in (-p/2, p/2].
func (f Field) Centered(a uint64) int64 {
	if a > f.p/2 {
		return int64(a) - int64(f.p)
	}
	return int64(a)
}

func (f Field) Add(a, b uint64) uint64 {
	s := a + b
	if s >= f.p {
		s -= f.p
	}
	return s
}

func (f Field) Sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + f.p - b
}

func (f Field) Neg(a uint64) uint64 {
	if a == 0 {
		return 0
	}
	return f.p - a
}

func (f Field) Mul(a, b uint64) uint64 { return mulmod(a, b, f.p) }

func (f Field) Pow(a, e uint64) uint64 { return powmod(a, e, f.p) }

// Inv returns the inverse of a by Fermat's little theorem (a^(p-2)).
func (f Field) Inv(a uint64) uint64 {
	if a%f.p == 0 {
		panic("inverse of zero")
	}
	return powmod(a, f.p-2, f.p)
}

func (f Field) VecFromInts(xs []int64) []uint64 {
	v := make([]uint64, len(xs))
	for i, x := range xs {
		v[i] = f.FromInt(x)
	}
	return v
}

func (f Field) Dot(a, b []uint64) uint64 {
	if len(a) != len(b) {
		panic("dot size mismatch")
	}
	s := uint64(0)
	for i := range a {
		s = f.Add(s, f.Mul(a[i], b[i]))
	}
	return s
}

func IsZero(a []uint64) bool {
	for _, x := range a {
		if x != 0 {
			return false
		}
	}
	return true
}
