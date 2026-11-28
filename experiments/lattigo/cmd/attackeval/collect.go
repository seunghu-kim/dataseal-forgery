// Command attackeval runs the attacks against the DataSeal verifiers under each
// evaluation-key profile.
package main

import (
	"dsfgo/attackrun"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if e := collectMain(os.Args[1:]); e != nil {
		if e == flag.ErrHelp {
			return
		}
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func collectMain(args []string) error {
	fs := flag.NewFlagSet("attackeval --collect", flag.ContinueOnError)
	enabled := fs.Bool("collect", false, "run the dataseal.trial.v1 collector (required)")
	repo := fs.String("repo", "../..", "repository root")
	out := fs.String("out", "", "NEW output directory (required)")
	meta := fs.String("metadata", "", "fresh current-machine environment JSON from existing offline tool (required)")
	schema := fs.String("schema", "", "dataseal.trial.v1 schema JSON (default: tools/validator)")
	validator := fs.String("validator", "", "validator executable (default: tools/validator)")
	mode := fs.String("mode", "fixed", "fixed or independent")
	trials := fs.Int("trials", 1, "measured input trials, per shape/scenario/profile")
	warmups := fs.Int("warmups", 0, "separate warmup input trials")
	seeds := fs.String("seeds", "", "comma-separated independent-mode uint64 root seeds; omit for fresh crypto/rand roots")
	sizes := fs.String("sizes", "", "n:d:ell:padded_dim comma-separated shapes")
	profiles := fs.String("profiles", "honest_minimal,extended", "explicit capability profiles")
	scenarios := fs.String("scenarios", "", "supported existing BFV scenarios, comma-separated; empty means all five")
	negative := fs.Bool("negative-controls", true, "record the existing missing-all-keys negative control")
	unsupported := fs.Bool("record-unsupported", true, "record that BFV zero-product implementation is absent")
	runID := fs.String("run-id", "A-"+time.Now().UTC().Format("20060102T150405.000000000Z"), "unique run identifier")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if !*enabled || len(fs.Args()) != 0 {
		return fmt.Errorf("usage: attackeval --collect [flags]; positional arguments are not accepted")
	}
	root, e := filepath.Abs(*repo)
	if e != nil {
		return e
	}
	defSchema, defValidator := attackrun.ValidatorPaths(root)
	if *schema == "" {
		*schema = defSchema
	}
	if *validator == "" {
		*validator = defValidator
	}
	roots, e := attackrun.ParseSeeds(*seeds)
	if e != nil {
		return e
	}
	shapes, e := attackrun.ParseSizes(*sizes)
	if e != nil {
		return e
	}
	selected := []string{}
	if *scenarios != "" {
		selected = strings.Split(*scenarios, ",")
	}
	c := attackrun.Config{Repository: root, Output: *out, Metadata: *meta, Schema: *schema, Validator: *validator, RunID: *runID, Mode: *mode, Trials: *trials, Warmups: *warmups, Seeds: roots, Sizes: shapes, Profiles: strings.Split(*profiles, ","), Scenarios: selected, NegativeControls: *negative, IncludeUnsupported: *unsupported, Arguments: append([]string{os.Args[0]}, args...)}
	s, e := attackrun.Run(c)
	fmt.Printf("records=%d evaluations=%d independent_input_units=%d statuses=%v\n", s.Records, s.Evaluations, s.IndependentInputUnits, s.ExecutionStatuses)
	return e
}
