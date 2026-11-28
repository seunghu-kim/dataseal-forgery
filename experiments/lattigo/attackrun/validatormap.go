package attackrun

import "dsfgo/bfvpack"

// ValidatorKeyProfile maps a key profile to the validator's evaluation_key_profile
// category: composite -> honest_minimal, direct_index -> extended, restricted
// profiles -> negative_control. The category cannot express the exact key set;
// KeyProvisioningDetail records it.
func ValidatorKeyProfile(internal string) (string, bool) {
	switch internal {
	case "composite":
		return "honest_minimal", true
	case "direct_index":
		return "extended", true
	case "squaring_only", "addition_only", "matmul_only":
		return "negative_control", true
	}
	return "", false
}

// KeyProvisioningDetail records the exact provisioned and used key sets and the
// composition chains.
func KeyProvisioningDetail(internal string, provisioned bfvpack.Capability, usedRot []int, usedRelin bool, synthChains map[int][]int) Record {
	enum, recognized := ValidatorKeyProfile(internal)
	okSub, extraRot, extraRelin := UsedWithinProvisioned(provisioned.Rotations, usedRot, provisioned.Relin, usedRelin)
	chains := Record{}
	lengths := Record{}
	for target, chain := range synthChains {
		key := itoa(target)
		chains[key] = append([]int{}, chain...)
		lengths[key] = len(chain)
	}
	return Record{
		"internal_key_profile":                     internal,
		"mapped_evaluation_key_profile":            enum,
		"mapping_recognized":                       recognized,
		"provisioned_rotation_keys":                unique(provisioned.Rotations),
		"provisioned_relinearization_key":          provisioned.Relin,
		"used_rotation_keys":                       unique(usedRot),
		"used_relinearization_key":                 usedRelin,
		"used_within_provisioned":                  okSub,
		"used_rotation_keys_outside_provisioned":   extraRot,
		"used_relinearization_outside_provisioned": extraRelin,
		"rotation_synthesis_chains":                chains,
		"rotation_synthesis_chain_lengths":         lengths,
		"detail_field_note":                        "recorded under schema additionalProperties:true; evaluation_key_profile carries only the mapped enum; validator cross-field partitioning acceptance is unverified",
	}
}

// itoa avoids importing strconv for one small use; targets are small signed ints.
func itoa(x int) string {
	if x == 0 {
		return "0"
	}
	neg := x < 0
	if neg {
		x = -x
	}
	var b [16]byte
	i := len(b)
	for x > 0 {
		i--
		b[i] = byte('0' + x%10)
		x /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
