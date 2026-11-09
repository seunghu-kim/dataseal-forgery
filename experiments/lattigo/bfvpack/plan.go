package bfvpack

import "fmt"

// Param is a BFV parameter candidate used by the capacity planner. RowSlots is
// N/2 because BFV RotateColumns is cyclic within each of the two N/2 slot
// halves; the row-major layouts here keep all data in the first half so a
// rotation never crosses the half boundary.
type Param struct {
	Name     string
	LogN     int
	N        int
	RowSlots int
}

// ParamByName returns the registry entry for a parameter set name.
func ParamByName(name string) (Param, bool) {
	for _, p := range Params {
		if p.Name == name {
			return p, true
		}
	}
	return Param{}, false
}

// Params is the fixed registry of pinned-backend parameter sets (t=65537 for
// all, so F_p is identical across them). PN16 is intentionally absent: it is not
// a pinned default and must not be silently introduced.
var Params = []Param{
	{"PN13QP218", 13, 8192, 4096},
	{"PN14QP438", 14, 16384, 8192},
	{"PN15QP880", 15, 32768, 16384},
}

// Strategy names.
const (
	StrategySingleCt = "single_ct"
	StrategyTiled    = "tiled"
	StrategyBlocked  = "blocked"
)

// MatmulPlan is the deterministic capacity/packing decision for one
// public-right matmul configuration. It is pure data derived from dimensions
// and the parameter registry, so it is unit-testable without any HE object.
type MatmulPlan struct {
	Scheme       string `json:"scheme"`
	N            int    `json:"n"`
	D            int    `json:"d"`
	Ell          int    `json:"ell"`
	ChecksumRows int    `json:"checksum_rows"`

	LogicalRows int `json:"logical_rows"` // n + checksum rows

	BaseParam string `json:"base_param"` // the single comparison group

	SingleCtDim    int    `json:"single_ct_dim"`
	SingleCtSlots  int    `json:"single_ct_slots"`
	SingleCtParam  string `json:"single_ct_param"`   // smallest param holding one ciphertext, "" if none in registry
	SingleCtBaseOK bool   `json:"single_ct_base_ok"` // fits one ciphertext at BaseParam

	TileSize       int  `json:"tile_size"`
	TileDim        int  `json:"tile_dim"`
	IBlocks        int  `json:"i_blocks"`
	KBlocks        int  `json:"k_blocks"`
	JBlocks        int  `json:"j_blocks"`
	InputTiles     int  `json:"input_tiles"`
	OutputTiles    int  `json:"output_tiles"`
	TileMultiplies int  `json:"tile_multiplies"`
	TileAdds       int  `json:"tile_adds"`
	TiledBaseOK    bool `json:"tiled_base_ok"` // tiles fit at BaseParam

	Strategy string `json:"strategy"`
	Reason   string `json:"reason"`
}

func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

func maxInt(xs ...int) int {
	m := xs[0]
	for _, x := range xs[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

// PlanMatmul computes the packing strategy for a public-right matmul of an
// (n+checksumRows) x d confidential operand by a public d x ell operand, with a
// chosen base comparison parameter set and tiling block size. The decision is:
// prefer a single ciphertext at baseParam; otherwise tile at baseParam;
// otherwise blocked.
func PlanMatmul(scheme string, n, d, ell, checksumRows, tileSize int, baseParam string) MatmulPlan {
	bp, ok := ParamByName(baseParam)
	if !ok {
		panic("unknown base param " + baseParam)
	}
	p := MatmulPlan{
		Scheme: scheme, N: n, D: d, Ell: ell, ChecksumRows: checksumRows,
		LogicalRows: n + checksumRows, BaseParam: baseParam, TileSize: tileSize,
	}

	// Single-ciphertext square-packed layout.
	p.SingleCtDim = maxInt(p.LogicalRows, d, ell)
	p.SingleCtSlots = p.SingleCtDim * p.SingleCtDim
	for _, cand := range Params {
		if p.SingleCtSlots <= cand.RowSlots {
			p.SingleCtParam = cand.Name
			break
		}
	}
	p.SingleCtBaseOK = p.SingleCtSlots <= bp.RowSlots

	// Tiled layout at baseParam.
	p.TileDim = tileSize
	p.IBlocks = ceilDiv(p.LogicalRows, tileSize)
	p.KBlocks = ceilDiv(d, tileSize)
	p.JBlocks = ceilDiv(ell, tileSize)
	p.InputTiles = p.IBlocks * p.KBlocks
	p.OutputTiles = p.IBlocks * p.JBlocks
	p.TileMultiplies = p.IBlocks * p.KBlocks * p.JBlocks
	p.TileAdds = p.OutputTiles * (p.KBlocks - 1)
	p.TiledBaseOK = tileSize*tileSize <= bp.RowSlots && tileSize >= 1

	switch {
	case p.SingleCtBaseOK:
		p.Strategy = StrategySingleCt
		p.Reason = fmt.Sprintf("fits one %s ciphertext (dim %d, %d/%d slots)",
			baseParam, p.SingleCtDim, p.SingleCtSlots, bp.RowSlots)
	case p.TiledBaseOK:
		p.Strategy = StrategyTiled
		p.Reason = fmt.Sprintf("tiled at %s T=%d: %dx%dx%d blocks, %d multiplies, %d adds",
			baseParam, tileSize, p.IBlocks, p.KBlocks, p.JBlocks, p.TileMultiplies, p.TileAdds)
	default:
		p.Strategy = StrategyBlocked
		p.Reason = fmt.Sprintf("tile dim %d exceeds %s row slots %d", tileSize, baseParam, bp.RowSlots)
	}
	return p
}
