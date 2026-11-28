package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const missing = "not_measured"
const version = "dataseal.trial.v1"

type Record map[string]any

var identityFields = strings.Fields("experiment_id run_id trial_id experiment_category workload implementation verifier input_dimensions seed parameter_profile evaluation_key_profile")
var correctnessFields = strings.Fields("expected_output actual_output output_difference error_magnitude wrong_output accepted attack_success mathematical_precondition precondition_satisfied")
var operationFields = strings.Fields("available_rotation_keys required_rotation_keys relinearization_key_available rotation_count ciphertext_multiplication_count plaintext_multiplication_count addition_count key_switch_count operation_count_source")
var timeFields = strings.Fields("preparation_time_ns encryption_time_ns evaluation_time_ns verification_time_ns decryption_time_ns total_time_ns")
var extraFields = strings.Fields("schema_version data_origin machine_id metadata_id time_unit workload_definition is_warmup timing_boundary execution_status error_message")
var optionalFields = strings.Fields("packing_time_ns direct_computation_time_ns program_preparation_time_ns input_reuse_programs reuse_policy program_family_id operation_count_scope sketch_p sketch_r sketch_Q_auth he_security_target_bits he_security_verified_bits estimator_evidence sample_mode independent_input input_unit_id input_digest_sha256 input_group_id paired_ciphertext_id duplicate_plaintext_input input_seed_independence seed_provenance required_relinearization_key attack_required_rotation_keys attack_required_relinearization_key attempted_operation_counts completed_operation_counts subtraction_count relinearization_count error_stack error_stage incomplete_timing_stage unsupported_capability_reason expected_augmented_output actual_augmented_output honest_decrypted_augmented_output verifier_checks precondition_evidence checksum_rows_unchanged kernel_delta_matches key_generation_time_ns honest_evaluation_time_ns honest_decryption_time_ns shared_pipeline_time_ns analysis_time_ns error_magnitude_definition")

func fields() []string {
	var f []string
	for _, x := range [][]string{identityFields, correctnessFields, operationFields, timeFields, extraFields} {
		f = append(f, x...)
	}
	return f
}
func text(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
func absent(v any) bool { return v == nil || text(v) == missing }
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		x, e := n.Float64()
		return x, e == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
func boolean(v any) (bool, bool) { b, ok := v.(bool); return b, ok }
func canonical(v any) string     { b, _ := json.Marshal(v); return string(b) }
func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte{239, 187, 191})))
	d.UseNumber()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

// All ingestion is offline. No observation is inferred from an outcome label.
func ReadRecords(path string) ([]Record, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return parseRecords(b, filepath.Ext(path))
}
func parseRecords(b []byte, extension string) ([]Record, error) {
	b = bytes.TrimPrefix(b, []byte{239, 187, 191})
	switch strings.ToLower(extension) {
	case ".csv":
		rd := csv.NewReader(bytes.NewReader(b))
		header, e := rd.Read()
		if e != nil {
			return nil, e
		}
		seen := map[string]bool{}
		for _, h := range header {
			if seen[h] {
				return nil, fmt.Errorf("duplicate CSV column %q", h)
			}
			seen[h] = true
		}
		out := []Record{}
		for line := 2; ; line++ {
			row, e := rd.Read()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, fmt.Errorf("CSV line %d: %w", line, e)
			}
			r := Record{}
			for i, h := range header {
				cell := row[i]
				var value any
				if cell == "" {
					value = missing
				} else if e := decode([]byte(cell), &value); e != nil {
					value = cell
				}
				r[h] = value
			}
			out = append(out, r)
		}
		return out, nil
	case ".jsonl":
		out := []Record{}
		s := bufio.NewScanner(bytes.NewReader(b))
		s.Buffer(make([]byte, 4096), 32<<20)
		line := 0
		for s.Scan() {
			line++
			if strings.TrimSpace(s.Text()) == "" {
				continue
			}
			var r Record
			if e := decode(s.Bytes(), &r); e != nil {
				return nil, fmt.Errorf("JSONL line %d: %w", line, e)
			}
			out = append(out, r)
		}
		return out, s.Err()
	default:
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, fmt.Errorf("empty input")
		}
		if bytes.TrimSpace(b)[0] == '[' {
			var out []Record
			e := decode(b, &out)
			return out, e
		}
		var r Record
		e := decode(b, &r)
		return []Record{r}, e
	}
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return exclusive(path, append(b, '\n'))
}
func exclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func WriteCSV(path string, rows []Record) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	cols := append(fields(), optionalFields...)
	if e = w.Write(cols); e != nil {
		return e
	}
	for _, r := range rows {
		line := make([]string, len(cols))
		for i, k := range cols {
			v, ok := r[k]
			if !ok {
				v = missing
			}
			if s, ok := v.(string); ok {
				line[i] = s
				var parsed any
				if decode([]byte(s), &parsed) == nil || s == "" {
					line[i] = canonical(s)
				}
			} else {
				line[i] = canonical(v)
			}
		}
		if e = w.Write(line); e != nil {
			return e
		}
	}
	w.Flush()
	return w.Error()
}

func JSONSchema() Record {
	properties := Record{}
	for _, k := range fields() {
		properties[k] = Record{"description": "Use not_measured for unavailable observations; see SCHEMA.md and offline cross-field validator."}
	}
	scalar := func(t string) Record { return Record{"anyOf": []any{Record{"type": t}, Record{"const": missing}}} }
	for _, k := range []string{"wrong_output", "accepted", "attack_success", "precondition_satisfied", "relinearization_key_available"} {
		properties[k] = scalar("boolean")
	}
	for _, k := range append(append([]string{}, timeFields...), "error_magnitude", "rotation_count", "ciphertext_multiplication_count", "plaintext_multiplication_count", "addition_count", "key_switch_count") {
		properties[k] = Record{"anyOf": []any{Record{"type": "number", "minimum": 0}, Record{"const": missing}}}
	}
	for _, k := range []string{"available_rotation_keys", "required_rotation_keys"} {
		properties[k] = Record{"anyOf": []any{Record{"type": "array", "items": Record{"type": "integer"}}, Record{"const": missing}}}
	}
	for _, k := range []string{"experiment_id", "run_id", "trial_id"} {
		properties[k] = Record{"type": "string", "pattern": idPattern.String()}
	}
	properties["schema_version"] = Record{"const": version}
	properties["time_unit"] = Record{"const": "ns"}
	properties["is_warmup"] = Record{"type": "boolean"}
	properties["data_origin"] = Record{"enum": []string{"synthetic_example", "fresh_measurement"}}
	properties["execution_status"] = Record{"enum": []string{"completed", "runtime_error", "panic", "unsupported_configuration", "timeout", "cancelled", "not_started"}}
	return Record{"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "DataSeal generic externally supplied per-trial observations", "type": "object", "required": fields(), "properties": properties, "additionalProperties": true, "description": "Structural aid; offline validator also enforces success consistency, errors, capability/profile partitioning, provenance and mathematical eligibility. No observation reconstruction."}
}
