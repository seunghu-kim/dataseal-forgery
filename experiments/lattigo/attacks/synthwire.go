package attacks

import "dsfgo/bfvpack"

type synthSession struct {
	generators []int
	chains     map[int][]int
}

// active is process-global: attacks run serially, so one session brackets one attack.
var active *synthSession

// BeginSynthesis sets the held rotation offsets for the next attack.
func BeginSynthesis(generators []int) {
	active = &synthSession{generators: append([]int{}, generators...), chains: map[int][]int{}}
}

// EndSynthesis returns the recorded chains; it is safe to call when no session
// started (e.g. a panic before the attack).
func EndSynthesis() map[int][]int {
	if active == nil {
		return map[int][]int{}
	}
	c := active.chains
	active = nil
	return c
}

// synthRotate composes the rotation from held keys when a session is active, else
// rotates directly. An unreachable target panics like a missing key.
func synthRotate(k bfvpack.Keys, c bfvpack.Cipher, target int) bfvpack.Cipher {
	if active == nil {
		return k.RotateCols(c, target)
	}
	out, chain, err := SynthesizedRotation(k, c, target, active.generators)
	if err != nil {
		panic(err)
	}
	active.chains[target] = append([]int{}, chain...)
	return out
}
