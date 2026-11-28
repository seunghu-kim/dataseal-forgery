# DataSeal per-trial schema v1

This is a generic format for externally supplied observations. It contains no experiment launcher or cryptographic implementation. `schema.json` is a machine-readable structural aid; the offline validator is authoritative for cross-field rules.

Every required column must be present. An unavailable observation is the literal JSON string **`"not_measured"`**, never null, blank-as-zero, false, or an invented estimate. The CSV importer treats an empty cell as `not_measured`; an absent column is an error. Exported CSV uses JSON syntax inside cells for arrays/objects/booleans/numbers and quotes ambiguous string literals so seed types survive round trips. JSON may be one record or an array; JSONL has one record per line. UTF-8 with or without BOM is accepted. Legacy aggregate/outcome schemas are not silently converted.

## Required identity fields

| Fields | Representation |
|---|---|
| `experiment_id`, `run_id`, `trial_id` | Nonmissing strings matching `[A-Za-z0-9][A-Za-z0-9_.:-]*`; composite ID must be unique across all profiles |
| `experiment_category` | `attack`, `performance`, or `correctness` |
| `workload` | Stable workload identifier |
| `implementation`, `verifier` | Explicit implementation and verifier names; `verifier="none"` means no acceptance observation exists |
| `input_dimensions` | Positive integer object, e.g. `{"n":32,"d":32,"ell":32,"padded_dim":34}` |
| `seed` | Recorded number, descriptor, or seed-map; use an explicit fixed-literal or unrecorded-OS-randomness descriptor when appropriate; never invent a seed |
| `parameter_profile` | Exact profile ID, e.g. `PN14QP438`; not a security guarantee |
| `evaluation_key_profile` | `honest_minimal`, `extended`, `negative_control`, `not_applicable`, or `not_measured` |

All fields allow `not_measured` except stable IDs, schema version, category, data origin, time unit, warmup classification, and execution status. Missing identity/precondition/boundary data generates explicit diagnostics and prevents cross-method comparison. Records without established compatibility are kept in separate per-trial analysis partitions rather than pooled.

## Required correctness fields

`expected_output`, `actual_output`, `output_difference`, `error_magnitude`, `wrong_output`, `accepted`, `attack_success`, `mathematical_precondition`, `precondition_satisfied`.

- Outputs/differences may be arrays, objects, or externally recorded digest/delta evidence. Describe the finite-field arithmetic or norm in the supplied object. The toolkit does not decrypt, recompute a scheme's result, or verify the claimed difference.
- `error_magnitude` is a nonnegative numeric value only when an operator has defined and measured it; otherwise `not_measured`.
- `wrong_output` and `accepted` are independent supplied booleans. No boolean is inferred from an outcome string, missing output, PASS, exception, or zero error magnitude.
- **`attack_success = wrong_output AND accepted`** when both observations exist. If either observation is missing, `attack_success` must be `not_measured`, even if the other boolean is false.
- Noncompleted executions must leave `attack_success=not_measured`. They are not attack failures. An interrupted run may retain a partially observed `wrong_output`; missing acceptance must remain missing.
- `mathematical_precondition` is an explicit expression/description, `none` when no condition applies, or `not_measured`. For a conditional attack, `precondition_satisfied` must be separately supplied true/false to establish eligibility. No rank/nonzero check is invented by this tool.
- `verifier="none"` requires `accepted=not_measured`. FHE-only correctness is not authentication.

## Required operation fields

`available_rotation_keys`, `required_rotation_keys`, `relinearization_key_available`, `rotation_count`, `ciphertext_multiplication_count`, `plaintext_multiplication_count`, `addition_count`, `key_switch_count`, `operation_count_source`.

Key lists are integer offset arrays or `not_measured`. Availability is a boolean or `not_measured`. Counts are nonnegative integers or `not_measured`. Key switching and relinearization are not inferred from multiplication or rotation totals.

`operation_count_source` is `measured`, `analytical`, `estimated`, or `not_measured`. For mixed provenance, supply an object mapping each known count field to its source. A known count with an unknown source is invalid. The optional `operation_count_scope` should state whether instrumentation counted completed operations, attempted operations, or both. Do not present attempted counters at a panic as completed work.

## Required timing/execution fields

`preparation_time_ns`, `encryption_time_ns`, `evaluation_time_ns`, `verification_time_ns`, `decryption_time_ns`, `total_time_ns`, `timing_boundary`, `execution_status`, `error_message`.

All numeric timings are nonnegative **nanoseconds**. The validator does not convert units. Additional `_ms`/`_seconds` fields are rejected to expose ambiguous imports. A batch-normalized timing may be fractional ns; record the batching definition in the boundary.

Example boundary structure:

```json
{
  "definition": "Input preparation and encryption, prepared-program server evaluation, decryption and verification; keygen and plaintext correctness reference excluded",
  "included_stages": ["preparation", "encryption", "evaluation", "decryption", "verification"],
  "program_preparation": "included in preparation",
  "packing_relation": "packing is included in encryption",
  "batch": 1,
  "thread_policy": "operator-recorded fixed settings"
}
```

Only a boundary object with a nonempty definition and explicit included stages permits comparisons. Every boundary member participates in compatibility matching. A bare string such as `server only` remains recorded but is too ambiguous for comparison. The tool cannot detect falsely described physical boundaries.

Execution status is one of `completed`, `runtime_error`, `panic`, `unsupported_configuration`, `timeout`, `cancelled`, `not_started`. Every noncompleted status requires an explicit reason/original error. The tool does not automatically turn a panic into unsupported capability or verifier rejection. Keep diagnoses separately in supplied structured evidence if needed.

## Additional required provenance fields

| Field | Meaning |
|---|---|
| `schema_version` | `dataseal.trial.v1` |
| `data_origin` | `fresh_measurement` or `synthetic_example`; declaration is not proof of freshness |
| `machine_id`, `metadata_id` | Operator linkage to a contemporaneous environment snapshot |
| `time_unit` | `ns` |
| `workload_definition` | Exact mathematical workload and input/packing contract: descriptive string or object containing `expression` |
| `is_warmup` | Explicit boolean; warmups are excluded from attempted/completed/statistical denominators |

Use `--metadata` to validate current-machine metadata linkage. One supplied metadata snapshot may cover many trials, but records from other metadata/machines/runs are not pooled. Evidence files and commands must be archived by the operator. The validator cannot determine whether an operator copied an old observation and relabeled it.

## Optional reporting extensions

- `packing_time_ns`, `direct_computation_time_ns`, `program_preparation_time_ns`: independent measured stage costs; never reconstructed from a total.
- `input_reuse_programs`: 1, 2, 4, or 8; `reuse_policy` and `program_family_id` identify compatible input-reuse workloads.
- `operation_count_scope`: attempted/completed counter semantics.
- `sketch_p=65537`, `sketch_r=10`, `sketch_Q_auth` in `[1,4294967296]`: required to establish the private-sketch reporting assumptions. Missing values remain unverified; incompatible supplied values are rejected.
- `he_security_target_bits=128`: target only. `he_security_verified_bits` requires operator-supplied `estimator_evidence`; this toolkit does not run or independently audit an estimator and does not promote a target to verified security.

## Statistical definitions

Non-warmup records with a status other than `not_started` count as attempted. Only `completed` records count as completed. Eligibility requires completion and either `mathematical_precondition="none"` or explicitly satisfied conditional preconditions.

The conditional success denominator is **eligible completed trials with both wrong_output and accepted observed**. The numerator is accepted incorrect outputs in that same set. Both are printed. The separate `accepted_incorrect_completed_trials` count preserves observed successes even when their mathematical eligibility remains unverified; it is not the conditional-success count. Zero denominator produces `not_measured`, not 0%.

Performance timing statistics use completed, precondition-eligible, non-warmup trials with `wrong_output=false` and verifier acceptance true where a verifier exists. Attack timing summaries use completed, precondition-eligible trials and are not restricted to successes. Every metric has its own observed sample count. Failures, unsupported configurations, warmups and missing values never become zero timings.

Median/Q1/Q3 use linear interpolation (R type 7); IQR=Q3−Q1. The primary performance repetition target uses valid `total_time_ns` samples: n≤64 requires 20; n=128 requires 10. Other shapes are explicitly marked without an assigned target. Each other timing metric also reports its actual count. An IQR of zero with one sample does not establish stability. No confidence intervals are generated because independence/sampling assumptions are not established by this schema.

`client_preparation_total_ns` is a labeled derived sum of the supplied preparation and encryption times only when both exist. Client-vs-direct plots use only records containing all three measurements, so their cohorts are paired. Figures never sum stage medians into a total. Packing breakdowns show separate, non-additive stage medians because packing can overlap other stages.

PN13 and PN14, honest-minimal and extended capabilities, different workloads/boundaries, origins, runs, machines, metadata snapshots and reuse cardinalities are kept separate. Cross-method plots omit implementation/verifier identity only from their compatibility key; the mathematical workload and remaining contracts must match exactly. Different authentication schemes are never claimed to have equal authentication security.

## Experiment A collector extensions (same v1 required fields)

The existing `cmd/attackeval --collect` can now supply real observations directly.
The reporting tool still does not launch it. Optional fields include sample_mode,
independent_input, input_unit_id, input_digest_sha256, paired_ciphertext_id, seed
provenance, required relin, completed/attempted operation details, subtraction/relin
counts, stacks/stages, extra baseline/keygen/analysis timings, and preservation
evidence. Raw JSONL retains all diagnostics. No prior raw results or synthetic
examples are automatically converted into new measurements.

`sample_mode` partitions fixed/reproduction/independent datasets. Declaring
`independent_input=true` requires sample_mode=independent and a 64-character
lowercase plaintext SHA-256 digest. It denotes unique plaintext sampling under
the declared protocol, not a proof of IID seeds. Digests exclude authentication
keys and encryption randomness.

Summary JSON and attack CSV include distinct plaintext counts and a separate
independent-input conditional success rate. Within each workload/run/HE/key/
verifier partition, the first non-warmup observation per declared-independent
digest is selected. Later re-encryptions/retries do not add independent samples;
successful retries are not preferentially selected. Only completed, eligible
selected records with both observations enter that denominator. Original
execution-trial rates remain separate. Fixed repetitions have no independent
input denominator. Missing hashes/declarations remain not_measured. No confidence
interval or verified seed independence is inferred.

The new collector's primary counts are completed evaluator calls, with separate
attempted totals. Ct multiplication completion can precede failed relin.
Addition excludes separately recorded subtraction. Key-switch counts remain
not_measured. Its total timing explicitly sums two disjoint observed intervals
for shared ciphertext work and one verifier; it is not monolithic wall time or
a sum of stage medians. See the collector README for exact boundaries.
