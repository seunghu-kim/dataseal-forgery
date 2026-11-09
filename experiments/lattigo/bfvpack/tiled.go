package bfvpack

import (
	"sort"

	"dsfgo/matrix"
)

// Tiled public-right matmul. A confidential operand is split into a grid of
// blocks, each packed row-major in one ciphertext with a common square stride
// Dim. The product by a public matrix is computed block-wise:
// C[I][J] = sum_K PublicRightMatmul(A[I][K], B[K][J]) accumulated with ct-ct
// adds. This reuses the verified single-ciphertext kernel and keeps one
// parameter group for every matrix size.
//
// Row and column block boundaries are explicit offset arrays, so the same
// implementation serves two layout policies:
//   - uniform (G7): equal RowTile=ColTile=Dim blocks.
//   - capacity_aware (F3): the trailing block row absorbs the DataSeal checksum
//     rows into otherwise-unused slots, using a larger Dim, instead of spending
//     a whole extra block row on them.

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

// uniformOffsets returns cumulative boundaries splitting total into tile-sized
// blocks (last may be short).
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

// capacityRowOffsets splits totalRows (= dataRows + trailing rows such as
// checksum rows) into exactly ceil(dataRows/tile) blocks, folding the trailing
// rows into the final block instead of starting a new one.
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

func maxOff(off []int) int {
	m := 0
	for _, l := range offLens(off) {
		if l > m {
			m = l
		}
	}
	return m
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

// EncryptTiled packs a logical matrix into a uniform grid of tileSize blocks.
func (k Keys) EncryptTiled(m matrix.Mat, tileSize int) TiledCipher {
	return k.encryptGrid(m, uniformOffsets(m.Rows(), tileSize), uniformOffsets(m.Cols(), tileSize), tileSize, tileSize)
}

// EncryptTiledCapacity packs a logical matrix whose last (m.Rows()-dataRows)
// rows are appended checksum rows, folding them into the final block row. The
// tile stride grows to Dim=max(largest row block, colTile) so the merged block
// still fits one ciphertext; if it would exceed RowSlots the caller should fall
// back to EncryptTiled.
func (k Keys) EncryptTiledCapacity(m matrix.Mat, dataRows, colTile int) TiledCipher {
	rowOff := capacityRowOffsets(dataRows, m.Rows(), colTile)
	colOff := uniformOffsets(m.Cols(), colTile)
	dim := colTile
	if r := maxOff(rowOff); r > dim {
		dim = r
	}
	return k.encryptGrid(m, rowOff, colOff, dim, colTile)
}

// CapacityTilingFits reports whether the capacity-aware layout fits one
// ciphertext half at the context's RowSlots.
func (c Context) CapacityTilingFits(totalRows, dataRows, colTile int) bool {
	rowOff := capacityRowOffsets(dataRows, totalRows, colTile)
	dim := colTile
	if r := maxOff(rowOff); r > dim {
		dim = r
	}
	return dim*dim <= c.RowSlots()
}

// TiledMatmulRotations returns the union of rotation offsets needed across all
// (inner-block, output-block) size pairs for a uniform tiled matmul.
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

// MatmulRotations returns the rotation offsets a tiled product of this operand
// by a public (Cols x outCols) matrix needs, matching the operand's own column
// blocking (so it is correct for both uniform and capacity layouts).
func (a TiledCipher) MatmulRotations(outCols int) []int {
	return tiledRotations(a.colOff, uniformOffsets(outCols, a.ColTile))
}

// PublicRightMatmulTiled computes Enc(A)->Enc(A*B) with B public, tiling the
// inner and output dimensions. The result is an output grid.
func (k Keys) PublicRightMatmulTiled(a TiledCipher, b matrix.Mat, outCols int) TiledCipher {
	if b.Rows() != a.Cols {
		panic("tiled matmul inner dimension mismatch")
	}
	if outCols > b.Cols() {
		panic("tiled matmul output columns exceed operand")
	}
	jOff := uniformOffsets(outCols, a.ColTile)
	jLens := offLens(jOff)
	kLens := offLens(a.colOff)
	out := TiledCipher{
		Rows: a.Rows, Cols: outCols, Dim: a.Dim, ColTile: a.ColTile,
		IBlocks: a.IBlocks, KBlocks: len(jLens),
		rowOff: a.rowOff, colOff: jOff,
		tiles: make([][]Cipher, a.IBlocks),
	}
	for i := 0; i < a.IBlocks; i++ {
		out.tiles[i] = make([]Cipher, len(jLens))
		for j := 0; j < len(jLens); j++ {
			var acc *Cipher
			for kk := 0; kk < a.KBlocks; kk++ {
				bBlk := blockOf(b, a.colOff[kk], jOff[j], kLens[kk], jLens[j])
				term := k.PublicRightMatmul(a.tiles[i][kk], bBlk, jLens[j])
				if acc == nil {
					t := term
					acc = &t
				} else {
					sum := k.Add(*acc, term)
					acc = &sum
				}
			}
			out.tiles[i][j] = *acc
		}
	}
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

// Bytes returns the total serialized size of all ciphertext tiles.
func (c TiledCipher) Bytes() int {
	total := 0
	for i := range c.tiles {
		for j := range c.tiles[i] {
			total += c.tiles[i][j].Bytes()
		}
	}
	return total
}

// NumTiles returns the number of ciphertext tiles in the grid.
func (c TiledCipher) NumTiles() int { return c.IBlocks * c.KBlocks }

// DecryptTiled reassembles the logical matrix from an output grid.
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
