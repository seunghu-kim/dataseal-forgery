package bfvpack

import (
	"sort"

	"dsfgo/matrix"
)

// Tiled matmul: the operand is split into blocks, one row-major ciphertext each,
// and C[I][J] = sum_K A[I][K]*B[K][J] reuses the single-ciphertext kernel.
// Layout policies: uniform blocks, or capacity_aware, where the last block row
// absorbs the DataSeal checksum rows instead of adding a block row.

type TiledCipher struct {
	Rows, Cols int // logical matrix dimensions
	Dim        int // common square stride of every tile
	ColTile    int // logical column block width
	IBlocks    int
	KBlocks    int
	tiles      [][]Cipher
	rowOff     []int // len IBlocks+1 cumulative row boundaries
	colOff     []int // len KBlocks+1 cumulative column boundaries
}

// TiledLayout is public geometry, independent of ciphertexts and private input.
type TiledLayout struct {
	Rows, Cols, Dim, ColTile int
	RowOffsets, ColOffsets   []int
}

func NewTiledLayout(rows, cols, dataRows, tile, stride int, capacity bool) TiledLayout {
	if rows < 1 || cols < 1 || dataRows < 1 || dataRows > rows || tile < 1 {
		panic("invalid tiled geometry")
	}
	ro := uniformOffsets(rows, tile)
	if capacity {
		ro = capacityRowOffsets(dataRows, rows, tile)
	}
	return TiledLayout{rows, cols, stride, tile, ro, uniformOffsets(cols, tile)}
}

func (c Context) validateTiledLayout(l TiledLayout) {
	if l.Rows < 1 || l.Cols < 1 || l.ColTile < 1 || l.Dim < 1 || l.Dim > c.RowSlots()/l.Dim {
		panic("invalid tiled capacity")
	}
	for _, pair := range []struct {
		off   []int
		total int
	}{{l.RowOffsets, l.Rows}, {l.ColOffsets, l.Cols}} {
		if len(pair.off) < 2 || pair.off[0] != 0 || pair.off[len(pair.off)-1] != pair.total {
			panic("invalid tile offsets")
		}
		for i := 1; i < len(pair.off); i++ {
			if pair.off[i] <= pair.off[i-1] || pair.off[i]-pair.off[i-1] > l.Dim {
				panic("tile exceeds stride")
			}
		}
	}
	if l.ColTile > l.Dim {
		panic("output tile exceeds stride")
	}
}

func (k Keys) EncryptTiledLayout(m matrix.Mat, l TiledLayout) TiledCipher {
	k.ctx.validateTiledLayout(l)
	if m.Rows() != l.Rows || m.Cols() != l.Cols {
		panic("tiled input shape mismatch")
	}
	return k.encryptGrid(m, append([]int(nil), l.RowOffsets...), append([]int(nil), l.ColOffsets...), l.Dim, l.ColTile)
}

// PreparedTiledMatmul holds encoded public masks only; it is prepared from
// Context, without keys or A.
type PreparedTiledMatmul struct {
	input         TiledLayout
	outputOffsets []int
	programs      [][][]PreparedMatmul
}

func (c Context) PrepareTiledMatmul(l TiledLayout, b matrix.Mat, outCols int) PreparedTiledMatmul {
	c.validateTiledLayout(l)
	if b.Rows() != l.Cols || outCols < 1 || outCols > b.Cols() {
		panic("tiled public operand shape mismatch")
	}
	l.RowOffsets = append([]int(nil), l.RowOffsets...)
	l.ColOffsets = append([]int(nil), l.ColOffsets...)
	p := PreparedTiledMatmul{input: l, outputOffsets: uniformOffsets(outCols, l.ColTile)}
	p.programs = make([][][]PreparedMatmul, len(l.RowOffsets)-1)
	public := Keys{ctx: c}
	for i, rows := range offLens(l.RowOffsets) {
		p.programs[i] = make([][]PreparedMatmul, len(p.outputOffsets)-1)
		for j, cols := range offLens(p.outputOffsets) {
			p.programs[i][j] = make([]PreparedMatmul, len(l.ColOffsets)-1)
			for kk, inner := range offLens(l.ColOffsets) {
				block := blockOf(b, l.ColOffsets[kk], p.outputOffsets[j], inner, cols)
				p.programs[i][j][kk] = public.PrepareMatmul(MakeLayout(rows, inner, rows, l.Dim), block, cols)
			}
		}
	}
	return p
}

// ServerTiledMatmul does prepared evaluation and tile accumulation only; no mask
// encoding happens here.
func (k Keys) ServerTiledMatmul(a TiledCipher, p PreparedTiledMatmul) TiledCipher {
	l := p.input
	equal := func(x, y []int) bool {
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	}
	if a.Rows != l.Rows || a.Cols != l.Cols || a.Dim != l.Dim || a.ColTile != l.ColTile || !equal(a.rowOff, l.RowOffsets) || !equal(a.colOff, l.ColOffsets) {
		panic("prepared tiled layout mismatch")
	}
	out := TiledCipher{Rows: a.Rows, Cols: p.outputOffsets[len(p.outputOffsets)-1], Dim: a.Dim, ColTile: a.ColTile, IBlocks: a.IBlocks, KBlocks: len(p.outputOffsets) - 1, rowOff: append([]int(nil), a.rowOff...), colOff: append([]int(nil), p.outputOffsets...), tiles: make([][]Cipher, a.IBlocks)}
	for i := range p.programs {
		out.tiles[i] = make([]Cipher, out.KBlocks)
		for j := range p.programs[i] {
			for kk, program := range p.programs[i][j] {
				term := k.ServerMatmul(a.tiles[i][kk], program)
				if kk == 0 {
					out.tiles[i][j] = term
				} else {
					out.tiles[i][j] = k.Add(out.tiles[i][j], term)
				}
			}
		}
	}
	return out
}

// uniformOffsets splits total into tile-sized blocks (the last may be short).
func uniformOffsets(total, tile int) []int {
	off := []int{0}
	for x := tile; x < total; x += tile {
		off = append(off, x)
	}
	off = append(off, total)
	if total == 0 {
		return []int{0, 0}
	}
	return off
}

// capacityRowOffsets folds trailing (checksum) rows into the last block instead
// of starting a new one.
func capacityRowOffsets(dataRows, totalRows, tile int) []int {
	nBlocks := ceilDiv(dataRows, tile)
	if nBlocks < 1 {
		nBlocks = 1
	}
	off := []int{0}
	for i := 1; i < nBlocks; i++ {
		off = append(off, i*tile)
	}
	off = append(off, totalRows)
	return off
}

func offLens(off []int) []int {
	out := make([]int, len(off)-1)
	for i := range out {
		out[i] = off[i+1] - off[i]
	}
	return out
}

func (k Keys) encryptGrid(m matrix.Mat, rowOff, colOff []int, dim, colTile int) TiledCipher {
	if dim*dim > k.ctx.RowSlots() {
		panic("tile dim exceeds row slots")
	}
	rowLens, colLens := offLens(rowOff), offLens(colOff)
	tc := TiledCipher{
		Rows: m.Rows(), Cols: m.Cols(), Dim: dim, ColTile: colTile,
		IBlocks: len(rowLens), KBlocks: len(colLens),
		rowOff: rowOff, colOff: colOff,
		tiles: make([][]Cipher, len(rowLens)),
	}
	for i := range rowLens {
		tc.tiles[i] = make([]Cipher, len(colLens))
		for j := range colLens {
			blk := blockOf(m, rowOff[i], colOff[j], rowLens[i], colLens[j])
			tc.tiles[i][j] = k.Encrypt(blk, MakeLayout(rowLens[i], colLens[j], rowLens[i], dim))
		}
	}
	return tc
}

// TiledMatmulRotations is the union of rotation offsets over all block size pairs.
func TiledMatmulRotations(inner, outCols, tileSize int) []int {
	return tiledRotations(uniformOffsets(inner, tileSize), uniformOffsets(outCols, tileSize))
}

func tiledRotations(kOff, jOff []int) []int {
	set := map[int]bool{}
	for _, kt := range offLens(kOff) {
		for _, jt := range offLens(jOff) {
			for _, d := range PublicMatmulRotations(kt, jt) {
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

func blockOf(m matrix.Mat, r0, c0, rows, cols int) matrix.Mat {
	blk := matrix.New(rows, cols)
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			blk.Set(r, c, m.At(r0+r, c0+c))
		}
	}
	return blk
}

func (c TiledCipher) Bytes() int {
	total := 0
	for i := range c.tiles {
		for j := range c.tiles[i] {
			total += c.tiles[i][j].Bytes()
		}
	}
	return total
}

func (c TiledCipher) NumTiles() int { return c.IBlocks * c.KBlocks }

func (k Keys) DecryptTiled(c TiledCipher) matrix.Mat {
	out := matrix.New(c.Rows, c.Cols)
	rowLens, colLens := offLens(c.rowOff), offLens(c.colOff)
	for i := 0; i < c.IBlocks; i++ {
		for j := 0; j < c.KBlocks; j++ {
			blk := k.Decrypt(c.tiles[i][j])
			for r := 0; r < rowLens[i]; r++ {
				for cc := 0; cc < colLens[j]; cc++ {
					out.Set(c.rowOff[i]+r, c.colOff[j]+cc, blk.At(r, cc))
				}
			}
		}
	}
	return out
}
