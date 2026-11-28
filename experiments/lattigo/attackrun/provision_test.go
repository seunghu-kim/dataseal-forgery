package attackrun

import (
	"reflect"
	"testing"

	"dsfgo/bfvpack"
)

func TestKeyProvisioningProfiles(t *testing.T) {
	matmul := bfvpack.PublicMatmulRotations(8, 6)
	if c := CompositeCapability(8, 6); !c.Relin || !reflect.DeepEqual(c.Rotations, matmul) {
		t.Fatalf("composite: relin=%v rot=%v", c.Relin, c.Rotations)
	}
	if c := MatmulOnlyCapability(8, 6); c.Relin || !reflect.DeepEqual(c.Rotations, matmul) {
		t.Fatalf("matmul-only must have rotations and no relin: %+v", c)
	}
	if c := SquaringOnlyCapability(); !c.Relin || len(c.Rotations) != 0 {
		t.Fatalf("squaring-only must be relin with no rotations: %+v", c)
	}
	if c := AdditionOnlyCapability(); c.Relin || len(c.Rotations) != 0 {
		t.Fatalf("addition-only must provision no keys: %+v", c)
	}
	attack := []int{96, -84}
	di := DirectIndexCapability(8, 6, attack)
	for _, o := range attack {
		if !containsInt(di.Rotations, o) {
			t.Fatalf("direct-index missing attack offset %d: %v", o, di.Rotations)
		}
	}
	if !di.Relin {
		t.Fatal("direct-index must keep relin")
	}
}

func TestProvisionedKeysDump(t *testing.T) {
	ctx := bfvpack.NewContext()
	got := ProvisionedKeys(ctx, bfvpack.Capability{Relin: true, Rotations: []int{1, -1, 5}})
	if !got.Relin {
		t.Fatal("relin key not reported present")
	}
	if !reflect.DeepEqual(unique(got.Rotations), []int{-1, 1, 5}) {
		t.Fatalf("materialized rotations = %v", got.Rotations)
	}
	none := ProvisionedKeys(ctx, bfvpack.Capability{})
	if none.Relin || len(none.Rotations) != 0 {
		t.Fatalf("empty capability materialized keys: %+v", none)
	}
}

func TestUsedWithinProvisioned(t *testing.T) {
	prov := []int{-5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7}
	if ok, extra, relin := UsedWithinProvisioned(prov, []int{-5, 7, 0}, true, false); !ok || len(extra) != 0 || relin {
		t.Fatalf("subset should hold: ok=%v extra=%v relin=%v", ok, extra, relin)
	}
	ok, extra, relin := UsedWithinProvisioned(prov, []int{7, 96}, false, true)
	if ok || !containsInt(extra, 96) || !relin {
		t.Fatalf("expected violation: ok=%v extra=%v relinExtra=%v", ok, extra, relin)
	}
}

func TestValidatorMappingAndDetail(t *testing.T) {
	cases := map[string]string{"composite": "honest_minimal", "direct_index": "extended",
		"squaring_only": "negative_control", "addition_only": "negative_control", "matmul_only": "negative_control"}
	for internal, want := range cases {
		if got, ok := ValidatorKeyProfile(internal); !ok || got != want {
			t.Fatalf("%s -> %q (ok=%v), want %q", internal, got, ok, want)
		}
	}
	if _, ok := ValidatorKeyProfile("unknown_profile"); ok {
		t.Fatal("unknown profile must not map")
	}
	detail := KeyProvisioningDetail("composite",
		bfvpack.Capability{Relin: true, Rotations: []int{-1, 1, 2}},
		[]int{1, 2}, false,
		map[int][]int{96: {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 5}})
	if detail["mapped_evaluation_key_profile"] != "honest_minimal" {
		t.Fatalf("mapped enum = %v", detail["mapped_evaluation_key_profile"])
	}
	if detail["used_within_provisioned"] != true {
		t.Fatalf("used should be within provisioned: %v", detail["used_within_provisioned"])
	}
	lengths, _ := detail["rotation_synthesis_chain_lengths"].(Record)
	if lengths["96"] != 14 {
		t.Fatalf("chain length for 96 = %v", lengths["96"])
	}
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
