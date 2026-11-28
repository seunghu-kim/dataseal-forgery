package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ldsec/lattigo/v2/bfv"

	"dsfgo/sketch"
	"dsfgo/veritas"
)

const (
	bMissing         = "not_measured"
	veritasPin       = "6e58ab505f81c03c1b71ffaf0dc29205293ba15a"
	tileCol          = 64 // BFV tile width
	repLambda        = 64
	repBlock         = 8
	peBlock          = 64
	maskNote         = "VERITAS public mask: adapter built from official primitives only. Extends the official MulScalar (same public constant on every replica/component) to a per-slot vector. No secret-key material used."
	oracleAssumption = "no verification oracle: the server never observes accept/reject outcomes"
)

type bRecord map[string]interface{}

type config struct {
	repo, out, meta, schema, validator, id, modfile string
	sizes                                           []int
	methods, packings                               []string
	trials, warmups                                 int
	seed                                            uint64
	peT                                             uint64
	stopOnError, memstats                           bool
	workload                                        string // matmul | element-add | element-square | reuse | compose
	programs                                        int    // reuse only: 1, 2, 4 or 8
	sketchRows                                      int    // matmul private_sketch only: 0 = sketch.RowsFor(65537,128,2^32) (default path)
}

// Private-sketch analytical parameters (default: r = RowsFor(p, lambda, Q_auth) = 10).
const (
	sketchP      = uint64(65537)
	sketchLambda = uint(128)
	sketchQAuth  = uint64(1 << 32)
)

// sketchRowsUsed is the r actually used: the override when > 0, else RowsFor.
func sketchRowsUsed(override int) int {
	if override > 0 {
		return override
	}
	return sketch.RowsFor(sketchP, sketchLambda, sketchQAuth)
}

// sketchBoundFields records r, its source and the forgery bounds; computed
// outside the timing boundary.
func sketchBoundFields(override int) bRecord {
	r := sketchRowsUsed(override)
	target := sketch.RowsFor(sketchP, sketchLambda, sketchQAuth)
	per := -float64(r) * math.Log2(float64(sketchP))
	union := math.Log2(float64(sketchQAuth)) + per
	src := "RowsFor(65537,128,2^32) default"
	if override > 0 {
		src = "override (--sketch-rows)"
	}
	unionText := fmt.Sprintf("Q_auth*p^-r = 2^32*65537^-%d ~ 2^%.2f", r, union)
	if union >= 0 {
		unionText += " (>= 1: vacuous, no guarantee over Q_auth=2^32 queries)"
	}
	return bRecord{
		"sketch_rows": r, "sketch_rows_source": src, "sketch_rows_target": target,
		"forgery_bound_per_attempt": fmt.Sprintf("p^-r = 65537^-%d ~ 2^%.2f", r, per), "forgery_bound_per_attempt_log2": per,
		"forgery_bound_union": unionText, "forgery_bound_union_log2": union,
		"security_below_target": r < target,
	}
}

// trialSecurity is the per-trial security block; only matmul private_sketch gets
// r-dependent fields.
func trialSecurity(c config, method string) bRecord {
	sec := methodSecurity(method, c.peT)
	if method == "private_sketch" && c.workload == "matmul" {
		sec = sketchSecurity(sec, c.sketchRows)
	}
	return sec
}

// sketchSecurity adds the bound fields for the r used.
func sketchSecurity(sec bRecord, override int) bRecord {
	for k, v := range sketchBoundFields(override) {
		sec[k] = v
	}
	if override > 0 {
		r := sketchRowsUsed(override)
		sec["authentication"] = fmt.Sprintf("private sketch p=65537, r=%d (override; target r=%d), Q_auth<=2^32", r, sec["sketch_rows_target"])
		sec["forgery_bound"] = fmt.Sprintf("%s; %s", sec["forgery_bound_per_attempt"], sec["forgery_bound_union"])
		if r < sec["sketch_rows_target"].(int) {
			sec["purpose"] = "cost comparison only (paper 4.3: r=1 sketch cost vs DataSeal); not a secure setting"
		}
	}
	return sec
}

var bfvMethods = map[string]bool{"bfv_only": true, "dataseal_original": true, "dataseal_strengthened": true, "private_sketch": true}
var veritasMethods = map[string]bool{"veritas_rep": true, "veritas_pe": true, "veritas_pe_t17": true}

func profileFor(method string, peT uint64) (string, bfv.ParametersLiteral) {
	lit := bfv.PN14QP438
	if method == "veritas_pe" {
		lit.T = peT
		return fmt.Sprintf("PN14QP438-T%d", new(big.Int).SetUint64(peT).BitLen()), lit
	}
	return "PN14QP438", lit
}

// checkPEModulus requires what the official VERITAS examples satisfy: t prime,
// t = 1 mod 2N, and t below every Q/P prime (so EncodeUintMul is valid). It also
// records whether t is maximal.
func checkPEModulus(t uint64) (bRecord, error) {
	lit := bfv.PN14QP438
	lit.T = t
	p, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		return nil, fmt.Errorf("lattigo rejects T=%d on PN14: %w", t, err)
	}
	all := append(append([]uint64{}, p.Q()...), p.P()...)
	minQP, collide := all[0], false
	for _, q := range all {
		if q < minQP {
			minQP = q
		}
		if q == t {
			collide = true
		}
	}
	m := uint64(2 * p.N())
	prime := new(big.Int).SetUint64(t).ProbablyPrime(40)
	largest := true
	for x := t + m; x < minQP; x += m {
		if new(big.Int).SetUint64(x).ProbablyPrime(40) {
			largest = false
			break
		}
	}
	rec := bRecord{"T": t, "bits": new(big.Int).SetUint64(t).BitLen(), "prime": prime, "T_mod_2N": t % m, "collides_with_Q_or_P": collide, "smallest_QP_prime": minQP, "below_every_QP_prime": t < minQP, "largest_valid_below_smallest_QP_prime": largest}
	if collide || !prime || t%m != 1 || t >= minQP || veritas.CheckPlaintextModulus(p) != nil {
		return rec, fmt.Errorf("PE modulus %d failed PN14 checks: %v", t, rec)
	}
	return rec, nil
}

func log2Bound(t uint64) float64 { return 1 - math.Log2(float64(t)) } // log2(2/t)

// methodSecurity documents authentication parameters and forgery bounds.
func methodSecurity(method string, peT uint64) bRecord {
	switch method {
	case "bfv_only":
		return bRecord{"authentication": "none (unauthenticated baseline)", "forgery_bound": "not_applicable"}
	case "dataseal_original", "dataseal_strengthened":
		return bRecord{"authentication": "DataSeal checksum rows; fixed key fixture K=rnd(seed 3), alpha=7", "forgery_bound": "no bound claimed (attack target in Experiment A)"}
	case "private_sketch":
		return bRecord{"authentication": "private sketch p=65537, r=10, Q_auth<=2^32", "forgery_bound": "Q_auth*p^-r <= 2^-128 (per query p^-10 ~ 2^-160)", "bound_status": "analytical", "assumptions": []string{"private client K", oracleAssumption}}
	case "veritas_rep":
		return bRecord{"authentication": "VERITAS REP (vche_1), lambda=64, |S|=32, t=65537", "forgery_bound": "~1/C(64,32) ~ 2^-60.7 (estimate; paper Thm 1 §IV-B, proof App. B: slot matching 2^-lambda)", "bound_status": "estimate", "assumptions": []string{oracleAssumption, "PRF (blake2b) security"}, "mask": maskNote}
	case "veritas_pe":
		return bRecord{"authentication": fmt.Sprintf("VERITAS PE (vche_2), NumReplications=1, t=%d", peT), "forgery_bound": fmt.Sprintf("~2/t ~ 2^%.1f (estimate via polynomial identity lemma, degree<=2; paper Thm 2 §V-B requires a lambda-bit prime t, proof App. C)", log2Bound(peT)), "bound_status": "estimate", "assumptions": []string{oracleAssumption, "PRF (blake2b) security"}, "mask": maskNote}
	case "veritas_pe_t17":
		return bRecord{"authentication": "VERITAS PE (vche_2), t=65537 (official PN14 micro-benchmark setting, vche_2/vche_2_benchmark_test.go:11-15)", "forgery_bound": fmt.Sprintf("~2/t ~ 2^%.1f (estimate)", log2Bound(65537)), "bound_status": "estimate", "security_below_target": true, "purpose": "sensitivity only: timing difference to the official PN14 bench setting", "assumptions": []string{oracleAssumption}, "mask": maskNote}
	}
	return bRecord{}
}

func writeNew(path string, value interface{}) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", " ")
	if e = enc.Encode(value); e != nil {
		return e
	}
	return f.Sync()
}

func readJSON(path string, v interface{}) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

func captured(v interface{}) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	if m, ok := v.(map[string]interface{}); ok && m["status"] == "completed" {
		if s, ok := m["stdout_stderr"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func gitOut(dir string, args ...string) (string, error) {
	b, e := exec.Command("git", append([]string{"-C", dir, "--no-optional-locks"}, args...)...).Output()
	return strings.TrimSpace(string(b)), e
}

// checkMetadata validates the offline environment snapshot for this run.
func checkMetadata(c config, profiles []string) (bRecord, error) {
	var m bRecord
	if e := readJSON(c.meta, &m); e != nil {
		return nil, e
	}
	host, e := os.Hostname()
	if e != nil {
		return nil, e
	}
	head, e := gitOut(c.repo, "rev-parse", "HEAD")
	if e != nil {
		return nil, e
	}
	stamp, e := time.Parse(time.RFC3339Nano, fmt.Sprint(m["timestamp_utc"]))
	if age := time.Since(stamp); e != nil || age < -time.Minute || age > 24*time.Hour {
		return nil, fmt.Errorf("metadata timestamp must be within 24 hours")
	}
	if m["schema_version"] != "dataseal.environment.v1" || m["machine_id"] != host || captured(m["git_commit"]) != head || m["metadata_id"] == nil {
		return nil, fmt.Errorf("metadata schema/machine/Git identity mismatch")
	}
	if m["warmup_count_operator_supplied"] != float64(c.warmups) || m["repetition_count_operator_supplied"] != float64(c.trials) {
		return nil, fmt.Errorf("metadata repetition/warmup plan mismatch")
	}
	if cmd, ok := m["exact_experiment_command_operator_supplied"].(string); !ok || strings.TrimSpace(cmd) == "" || strings.Contains(cmd, "NOT EXECUTED") {
		return nil, fmt.Errorf("exact operator command required")
	}
	if th, ok := m["thread_environment"].(map[string]interface{}); !ok || th["GOMAXPROCS"] != "1" {
		return nil, fmt.Errorf("metadata must record GOMAXPROCS=1 in thread_environment")
	}
	have := map[string]bool{}
	if list, ok := m["bfv_parameter_profiles_operator_supplied"].([]interface{}); ok {
		for _, p := range list {
			have[fmt.Sprint(p)] = true
		}
	}
	for _, p := range profiles {
		if !have[p] {
			return nil, fmt.Errorf("metadata missing selected profile %s", p)
		}
	}
	return m, nil
}

// checkVeritasPin requires the official checkout at the pinned commit and clean.
func checkVeritasPin(repo string) (bRecord, error) {
	dir := filepath.Join(repo, "external", "veritas")
	head, e := gitOut(dir, "rev-parse", "HEAD")
	if e != nil {
		return nil, e
	}
	status, e := gitOut(dir, "status", "--porcelain=v1")
	if e != nil {
		return nil, e
	}
	rec := bRecord{"head": head, "status_porcelain": status, "clean": status == ""}
	if head != veritasPin || status != "" {
		return rec, fmt.Errorf("external/veritas must be %s and clean (got %s, status %q)", veritasPin, head, status)
	}
	return rec, nil
}

func sha256File(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// sourceHashes covers every source file that can affect the measured code paths.
func sourceHashes(c config) (bRecord, error) {
	out := bRecord{}
	dirs := []string{"experiments/lattigo/cmd/efficiencyeval", "experiments/lattigo/veritas", "experiments/lattigo/bfvpack", "experiments/lattigo/dataseal", "experiments/lattigo/sketch", "experiments/lattigo/field", "experiments/lattigo/matrix", "external/veritas/vche", "external/veritas/vche_1", "external/veritas/vche_2"}
	for _, d := range dirs {
		files, e := filepath.Glob(filepath.Join(c.repo, d, "*.go"))
		if e != nil {
			return nil, e
		}
		sort.Strings(files)
		for _, f := range files {
			h, e := sha256File(f)
			if e != nil {
				return nil, e
			}
			rel, _ := filepath.Rel(c.repo, f)
			out[filepath.ToSlash(rel)] = h
		}
	}
	extra := []string{filepath.Join(c.repo, "experiments/lattigo/go.mod"), filepath.Join(c.repo, "experiments/lattigo/go.sum"), filepath.Join(c.repo, "external/veritas/go.mod"), c.schema, c.validator}
	if c.modfile != "" {
		extra = append(extra, c.modfile, strings.TrimSuffix(c.modfile, ".mod")+".sum")
	}
	for _, f := range extra {
		h, e := sha256File(f)
		if e != nil {
			return nil, e
		}
		out[filepath.ToSlash(f)] = h
	}
	if exe, e := os.Executable(); e == nil {
		if h, e := sha256File(exe); e == nil {
			out["executable:"+filepath.ToSlash(exe)] = h
		}
	}
	return out, nil
}

// parametersRecord documents profiles and per-method authentication settings.
func parametersRecord(c config) (bRecord, error) {
	profiles := []bRecord{}
	seen := map[string]bool{}
	for _, m := range c.methods {
		name, lit := profileFor(m, c.peT)
		if seen[name] {
			continue
		}
		seen[name] = true
		p, e := bfv.NewParametersFromLiteral(lit)
		if e != nil {
			return nil, e
		}
		rec := bRecord{"name": name, "N": p.N(), "T": p.T(), "logQ": p.LogQ(), "logQP": p.LogQP(), "Q": p.Q(), "P": p.P(), "sigma": p.Sigma(), "public_plaintext_mul_encoding": veritas.PublicMaskEncoding, "t_below_every_QP_prime": veritas.CheckPlaintextModulus(p) == nil, "he_security": heSecurity}
		if name != "PN14QP438" {
			chk, e := checkPEModulus(p.T())
			if e != nil {
				return nil, e
			}
			rec["pe_modulus_checks"] = chk
			rec["note"] = peModulusNote
			rec["lattigo_constraint"] = "bfv.NewParameters requires t <= Q[0] (lattigo bfv/params.go:126-127); default EncodeUintMul (RingTToMul) additionally requires t below every q_i"
		}
		profiles = append(profiles, rec)
	}
	methods := bRecord{}
	for _, m := range c.methods {
		name, _ := profileFor(m, c.peT)
		sec := methodSecurity(m, c.peT)
		if m == "private_sketch" && c.workload == "matmul" {
			sec = sketchSecurity(sec, c.sketchRows)
		}
		sec["parameter_profile"] = name
		switch {
		case bfvMethods[m]:
			sec["encryption"], sec["evaluation_keys"] = "public-key (bfvpack.KeyGen GenKeyPair)", "rotation keys only (no relinearisation, no row swap)"
			sec["packing"] = "controlled: stride n+2 (tiled: 66); native: stride n (DataSeal n+2; tiled 64/66); n=128 tiled T=64"
			sec["program_sharing"] = "per_row_block (B-2 PrepareTiledMatmul structure)"
		default:
			block := repBlock
			if m != "veritas_rep" {
				block = peBlock
			}
			sec["encryption"], sec["evaluation_keys"] = "public-key (official GenPublicKey + NewEncryptor(*PublicKey))", "rotation keys only (no relinearisation, no row swap)"
			sec["packing"] = fmt.Sprintf("native only: row-major stride = block size; block %d (single ciphertext when n <= block)", block)
			sec["block_size"] = block
			sec["program_sharing"] = "shared_across_row_blocks (public data reuse, same nature as BFV public masks)"
			if m == "veritas_rep" {
				sec["replication_lambda"] = repLambda
			}
		}
		methods[m] = sec
	}
	return bRecord{"boundary_version": boundaryVersion, "profiles": profiles, "methods": methods, "sketch_rows": sketchRowsUsed(c.sketchRows), "sketch_rows_source": sketchBoundFields(c.sketchRows)["sketch_rows_source"], "assumptions": []string{oracleAssumption}}, nil
}

// heSecurity documents the basis of the 128-bit classical claim for PN14QP438.
var heSecurity = bRecord{
	"target": "128-bit classical",
	"basis": []string{
		"Lattigo preset: bfv.DefaultParams (incl. PN14QP438) documented as 'ensuring 128 bit security in the classic setting' (lattigo v2.2.1-0.20210923173451 bfv/params.go:92-93)",
		"HomomorphicEncryption.org security standard (Albrecht et al., 2018), classical 128-bit table: N=2^14 allows log2(QP) <= 438 for a uniform ternary secret with sigma ~ 3.2; PN14QP438 has logQP = 438 (at the bound, includes the key-switching modulus P)",
		"secret distribution: rlwe GenSecretKey = ternary with P(0)=P(+1)=P(-1)=1/3 (rlwe/keygen.go:61-62, ring/ring_sampler_ternary.go:20-23); error sigma = 3.2 (rlwe/params.go:27)",
		"the plaintext modulus t does not enter the RLWE hardness estimate, so the PN14QP438-T54 profile (only T changed) keeps the same basis",
	},
	"estimator":     "lattice-estimator not run (not available offline in this environment); the claim rests on the standard table and the Lattigo preset documentation",
	"verified_bits": bMissing,
}

// peModulusNote is the parameters.json wording for the PE modulus.
const peModulusNote = "PE T: same approach as the VERITAS application examples (BFV preset kept, only T enlarged). Largest PN14 prime (54-bit) satisfying the condition of the official examples, t < every Q prime. Not a value from the official examples. Forgery probability ≈2^-53 (estimate)."

// validatorPaths returns the default schema and executable under tools/validator.
func validatorPaths(root string) (schema, exe string) {
	dir := filepath.Join(root, "tools", "validator")
	exe = filepath.Join(dir, "validator")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	return filepath.Join(dir, "schema.json"), exe
}
