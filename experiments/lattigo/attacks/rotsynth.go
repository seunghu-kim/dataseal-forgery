package attacks

import (
	"fmt"
	"sort"

	"dsfgo/bfvpack"
)

// DecomposeRotation writes target as a sum of held offsets, greedily taking the
// largest same-sign offset; it always succeeds when ±1 are held, as in the honest key set.
func DecomposeRotation(target int, generators []int) ([]int, error) {
	gens := normalizeGenerators(generators)
	if target == 0 {
		return []int{}, nil
	}
	if len(gens) == 0 {
		return nil, fmt.Errorf("cannot synthesize rotation by %d: no held rotation generators", target)
	}
	chain := []int{}
	rem := target
	maxSteps := abs(target) + 1 // guard; |rem| strictly decreases each step
	for step := 0; rem != 0; step++ {
		if step > maxSteps {
			return nil, fmt.Errorf("rotation decomposition for %d did not terminate (remainder %d, generators %v)", target, rem, gens)
		}
		g, ok := pickGenerator(rem, gens)
		if !ok {
			return nil, fmt.Errorf("cannot synthesize rotation by %d from held generators %v: stuck at remainder %d", target, gens, rem)
		}
		chain = append(chain, g)
		rem -= g
	}
	return chain, nil
}

func pickGenerator(rem int, gens []int) (int, bool) {
	best, found := 0, false
	for _, g := range gens {
		if (rem > 0) != (g > 0) {
			continue
		}
		if abs(g) > abs(rem) {
			continue
		}
		if !found || abs(g) > abs(best) {
			best, found = g, true
		}
	}
	return best, found
}

// SynthesizedRotation rotates c by target by chaining rotations over held keys
// only; each step is counted by the operation meter.
func SynthesizedRotation(k bfvpack.Keys, c bfvpack.Cipher, target int, generators []int) (bfvpack.Cipher, []int, error) {
	chain, err := DecomposeRotation(target, generators)
	if err != nil {
		return bfvpack.Cipher{}, nil, err
	}
	held := map[int]bool{}
	for _, g := range normalizeGenerators(generators) {
		held[g] = true
	}
	out := c
	for _, g := range chain {
		if !held[g] { // defensive: never request a key outside the held set
			return bfvpack.Cipher{}, nil, fmt.Errorf("refusing rotation by %d: not a held generator", g)
		}
		out = k.RotateCols(out, g)
	}
	return out, chain, nil
}

func normalizeGenerators(generators []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, g := range generators {
		if g == 0 || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	sort.Ints(out)
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
