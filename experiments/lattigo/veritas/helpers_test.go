package veritas

import (
	"dsfgo/field"
	"dsfgo/matrix"
)

func vmat(f field.Field, r, c int, seed uint64) matrix.Mat {
	m := matrix.New(r, c)
	s := seed*2862933555777941757 + 3037000493
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			s = s*6364136223846793005 + 1442695040888963407
			m.Set(i, j, (s>>11)%f.P())
		}
	}
	return m
}
