// Package attackrun runs the attacks under each evaluation-key profile and
// writes one record per verifier.
package attackrun

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const Missing = "not_measured"
const SchemaVersion = "dataseal.trial.v1"

type Record map[string]interface{}
type Size struct{ N, D, Ell, Dim int }
type Config struct {
	Repository, Output, Metadata, Schema, Validator, RunID, Mode string
	Trials, Warmups                                              int
	Seeds                                                        []uint64
	Sizes                                                        []Size
	Profiles, Scenarios                                          []string
	NegativeControls, IncludeUnsupported                         bool
	Arguments                                                    []string
}

var scenarios = []string{"selective_scaling", "matmul_kernel", "addition_kernel", "square_permute", "square_rescale"}
var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

func (c *Config) Validate() error {
	if !validID.MatchString(c.RunID) || c.RunID == Missing {
		return fmt.Errorf("run ID must be a nonmissing stable identifier")
	}
	if c.Output == "" || c.Metadata == "" || c.Schema == "" || c.Validator == "" {
		return fmt.Errorf("output, current-machine metadata, v1 schema and existing offline validator are required")
	}
	if c.Trials < 1 || c.Warmups < 0 {
		return fmt.Errorf("trials >=1 and warmups >=0 required")
	}
	if c.Mode != "fixed" && c.Mode != "independent" {
		return fmt.Errorf("mode must be fixed or independent")
	}
	if len(c.Seeds) > 0 && c.Mode != "independent" {
		return fmt.Errorf("explicit input seeds apply only to independent mode")
	}
	if len(c.Seeds) > 0 && len(c.Seeds) != c.Trials {
		return fmt.Errorf("supply exactly one root input seed per measured trial")
	}
	seen := map[uint64]bool{}
	for _, s := range c.Seeds {
		if seen[s] {
			return fmt.Errorf("duplicate input seed %d; repeated encryption is not an independent input trial", s)
		}
		seen[s] = true
	}
	if len(c.Sizes) == 0 {
		if c.Mode == "fixed" {
			c.Sizes = []Size{{3, 2, 2, 5}}
		} else {
			c.Sizes = []Size{{3, 5, 2, 8}, {8, 8, 6, 12}}
		}
	}
	if c.Mode == "fixed" && (len(c.Sizes) != 1 || c.Sizes[0] != (Size{3, 2, 2, 5})) {
		return fmt.Errorf("fixed mode preserves the existing 3x2 fixture and padded dimension 5")
	}
	shapes := map[Size]bool{}
	for _, s := range c.Sizes {
		if s.N < 3 || s.D < 2 || s.Ell < 1 || s.Dim < s.N+2 || s.Dim < s.D || s.Dim < s.Ell || s.Dim > 90 {
			return fmt.Errorf("invalid single-ciphertext PN14 shape %+v (n>=3,d>=2, padded dimension<=90)", s)
		}
		if shapes[s] {
			return fmt.Errorf("duplicate shape %+v", s)
		}
		shapes[s] = true
	}
	if len(c.Profiles) == 0 {
		c.Profiles = []string{"honest_minimal", "extended"}
	}
	allowedProfiles := map[string]bool{
		"honest_minimal": true, "extended": true,
		"composite": true, "squaring_only": true, "addition_only": true,
		"matmul_only": true, "direct_index": true,
	}
	pseen := map[string]bool{}
	for _, p := range c.Profiles {
		if !allowedProfiles[p] || pseen[p] {
			return fmt.Errorf("invalid or duplicate key profile %q", p)
		}
		pseen[p] = true
	}
	if len(c.Scenarios) == 0 {
		c.Scenarios = append([]string{}, scenarios...)
	}
	seenS := map[string]bool{}
	for _, s := range c.Scenarios {
		ok := false
		for _, known := range scenarios {
			ok = ok || s == known
		}
		if !ok || seenS[s] {
			return fmt.Errorf("unknown or duplicate BFV scenario %q", s)
		}
		seenS[s] = true
	}
	return nil
}
func ParseSeeds(s string) ([]uint64, error) {
	if s == "" {
		return nil, nil
	}
	out := []uint64{}
	for _, v := range strings.Split(s, ",") {
		x, e := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, nil
}
func ParseSizes(s string) ([]Size, error) {
	if s == "" {
		return nil, nil
	}
	out := []Size{}
	for _, part := range strings.Split(s, ",") {
		var z Size
		vals := strings.Split(part, ":")
		if len(vals) != 4 {
			return nil, fmt.Errorf("shape must be n:d:ell:padded_dim")
		}
		a := []*int{&z.N, &z.D, &z.Ell, &z.Dim}
		for i, v := range vals {
			x, e := strconv.Atoi(v)
			if e != nil {
				return nil, e
			}
			*a[i] = x
		}
		out = append(out, z)
	}
	return out, nil
}
func randomSeeds(n int) ([]uint64, error) {
	out := []uint64{}
	seen := map[uint64]bool{}
	for len(out) < n {
		var b [8]byte
		if _, e := rand.Read(b[:]); e != nil {
			return nil, e
		}
		v := binary.LittleEndian.Uint64(b[:])
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out, nil
}

type schema struct {
	Required   []string `json:"required"`
	Properties map[string]struct {
		Const string `json:"const"`
	} `json:"properties"`
}

func loadSchema(path string) (schema, error) {
	var s schema
	b, e := os.ReadFile(path)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, e
	}
	if s.Properties["schema_version"].Const != SchemaVersion || len(s.Required) < 40 {
		return s, fmt.Errorf("not the existing dataseal.trial.v1 schema")
	}
	return s, nil
}
func writeNew(path string, v interface{}) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	_, e = f.Write(append(b, '\n'))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func absolute(p string) string {
	x, e := filepath.Abs(p)
	if e != nil {
		return p
	}
	return x
}
