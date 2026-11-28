package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func output(path string, v any) error {
	if path != "" {
		return WriteJSON(path, v)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func withMetadata(rows []Record, v Validation, path string) (Validation, error) {
	if path == "" {
		hasMeasured := false
		for _, r := range rows {
			hasMeasured = hasMeasured || r["data_origin"] == "fresh_measurement"
		}
		if hasMeasured {
			v.Issues = append(v.Issues, Issue{"warning", 0, "provenance", "freshness is operator-declared; no metadata supplied for linkage"})
		}
		return v, nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return v, e
	}
	var m Record
	if e = decode(b, &m); e != nil {
		return v, e
	}
	if e = validateMetadata(m); e != nil {
		return v, e
	}
	for i, r := range rows {
		if r["data_origin"] != "fresh_measurement" {
			continue
		}
		if r["metadata_id"] != m["metadata_id"] || r["machine_id"] != m["machine_id"] {
			v.Valid = false
			v.Issues = append(v.Issues, Issue{"error", i + 1, "provenance", "record machine_id/metadata_id does not match supplied environment metadata"})
		}
	}
	return v, nil
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: validator <validate|analyze|report|environment|examples> [flags]; this tool never runs experiments")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	input := fs.String("input", "", "operator-supplied CSV/JSON/JSONL")
	out := fs.String("out", "", "NEW report/examples directory or NEW JSON output file")
	meta := fs.String("metadata", "", "optional current-machine environment JSON linkage")
	repo := fs.String("repo", ".", "repository root, read-only metadata collection")
	operator := fs.String("command", "", "exact experiment command recorded verbatim as data, NEVER executed")
	boundary := fs.String("boundary", "", "operator-supplied timing definition")
	profiles := fs.String("profiles", "", "operator-supplied comma-separated profile IDs")
	warmups := fs.Int("warmups", -1, "operator-supplied warmup count")
	repeats := fs.Int("repetitions", -1, "operator-supplied repetitions")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if len(fs.Args()) > 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	switch cmd {
	case "schema":
		return output(*out, JSONSchema())
	case "examples":
		if *out == "" {
			return fmt.Errorf("--out NEW_DIR required")
		}
		return writeExamples(*out)
	case "environment":
		if *operator == "" || *boundary == "" || *profiles == "" || *warmups < 0 || *repeats < 1 {
			return fmt.Errorf("environment requires --command --boundary --profiles --warmups >=0 --repetitions >=1")
		}
		root, e := filepath.Abs(*repo)
		if e != nil {
			return e
		}
		return output(*out, collectEnvironment(root, *operator, *boundary, *profiles, *warmups, *repeats))
	case "validate", "analyze", "report":
		if *input == "" {
			return fmt.Errorf("--input required")
		}
		rawInput, e := os.ReadFile(*input)
		if e != nil {
			return e
		}
		rows, e := parseRecords(rawInput, filepath.Ext(*input))
		if e != nil {
			return e
		}
		v, e := withMetadata(rows, Validate(rows), *meta)
		if e != nil {
			return e
		}
		if cmd == "validate" {
			if e = output(*out, v); e != nil {
				return e
			}
			if !v.Valid {
				return fmt.Errorf("result validation failed")
			}
			return nil
		}
		if !v.Valid {
			output("", v)
			return fmt.Errorf("refusing analysis/report of invalid records")
		}
		if cmd == "analyze" {
			return output(*out, Record{"validation": v, "statistics": Analyze(rows), "security_statement": "128-bit HE security is a target unless estimator evidence is supplied; authentication security is not equated across schemes"})
		}
		if *out == "" {
			return fmt.Errorf("report requires --out NEW_DIR")
		}
		if e = GenerateReport(rows, *out); e != nil {
			return e
		}
		h := sha256.Sum256(rawInput)
		absolute, e := filepath.Abs(*input)
		if e != nil {
			return e
		}
		if e = WriteJSON(filepath.Join(*out, "input-provenance.json"), Record{"operator_supplied_input_path": absolute, "input_sha256": hex.EncodeToString(h[:]), "input_bytes": len(rawInput), "raw_input_modified": false, "freshness_verified": false, "note": "Input fingerprint links figures to the exact bytes parsed; it does not establish freshness. No historical dataset loaded automatically."}); e != nil {
			return e
		}
		if len(v.Issues) > 0 { // preserve metadata-specific diagnostics separately, without mutating raw data
			return WriteJSON(filepath.Join(*out, "provenance-validation.json"), v)
		}
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q; no experiment execution commands exist", cmd)
	}
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
