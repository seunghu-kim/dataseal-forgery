package attackrun

import (
	"sort"

	"dsfgo/bfvpack"
)

// Evaluation-key profiles; one rotation key per distinct nonzero offset.

// CompositeCapability is the honest configuration: the matmul rotation keys and
// the squaring relin key.
func CompositeCapability(d, ell int) bfvpack.Capability {
	return bfvpack.Capability{Relin: true, Rotations: bfvpack.PublicMatmulRotations(d, ell)}
}

// MatmulOnlyCapability is the restricted configuration without the relin key (-Relin).
func MatmulOnlyCapability(d, ell int) bfvpack.Capability {
	return bfvpack.Capability{Relin: false, Rotations: bfvpack.PublicMatmulRotations(d, ell)}
}

// SquaringOnlyCapability is the restricted configuration without rotation keys (-Rot).
func SquaringOnlyCapability() bfvpack.Capability {
	return bfvpack.Capability{Relin: true}
}

// AdditionOnlyCapability is the restricted configuration with no evaluation keys (-Both).
func AdditionOnlyCapability() bfvpack.Capability {
	return bfvpack.Capability{}
}

// DirectIndexCapability adds the attack's own offsets as keys, so the attack
// needs no rotation composition (reference only).
func DirectIndexCapability(d, ell int, attackOffsets []int) bfvpack.Capability {
	rot := append([]int{}, bfvpack.PublicMatmulRotations(d, ell)...)
	rot = append(rot, attackOffsets...)
	return bfvpack.Capability{Relin: true, Rotations: unique(rot)}
}

// ProvisionedKeys reports the keys KeyGen actually created.
func ProvisionedKeys(ctx bfvpack.Context, cap bfvpack.Capability) bfvpack.Capability {
	return ctx.KeyGen(cap).AvailableEvaluationKeys()
}

// UsedWithinProvisioned reports whether the keys an attack used are a subset of
// the provisioned ones, and the extras if not.
func UsedWithinProvisioned(provisionedRot, usedRot []int, provisionedRelin, usedRelin bool) (ok bool, extraRot []int, extraRelin bool) {
	set := map[int]bool{}
	for _, r := range provisionedRot {
		set[r] = true
	}
	for _, u := range usedRot {
		if u != 0 && !set[u] {
			extraRot = append(extraRot, u)
		}
	}
	extraRot = unique(extraRot)
	sort.Ints(extraRot)
	extraRelin = usedRelin && !provisionedRelin
	ok = len(extraRot) == 0 && !extraRelin
	return ok, extraRot, extraRelin
}
