# attackrun

Collector for the attack experiment (Table 1). `cmd/attackeval --collect` runs
each attack in `attacks` on BFV ciphertexts under several evaluation-key
profiles and submits the result to the DataSeal verifiers in `dataseal`.
It writes one JSON record per input, attack, profile, and verifier.

## Key profiles

| Profile         | Keys given to the server                                      | In the paper                       |
|-----------------|---------------------------------------------------------------|------------------------------------|
| `composite`     | rotation keys of matrix multiplication, relin key of squaring | honest configuration               |
| `matmul_only`   | rotation keys only                                            | restricted: no relinearization key |
| `squaring_only` | relinearization key only                                      | restricted: no rotation keys       |
| `addition_only` | none                                                          | restricted: neither                |
| `direct_index`  | the `composite` keys plus the attack's own rotation offsets   | reference without composition      |

If a profile lacks a key that the honest evaluation or the attack needs, the
run stops at that operation. The record keeps the error (`execution_status` is
`panic`) and names the missing key (`missing_rotation_keys`,
`missing_relinearization_key`, `unsupported_capability_reason`); it is not
counted as a rejection by a verifier (`accepted` is `not_measured`).
Verifier labels `dataseal_original`, `dataseal_strengthened`, and
`dataseal_appendix` are the original checks, the corrected check, and the
variant of DataSeal's Appendix A.

## Running

    cd experiments/lattigo
    go run ./cmd/attackeval --collect --mode independent --trials 20 --warmups 1 \
      --profiles composite,matmul_only,squaring_only,addition_only,direct_index \
      --repo <repo> --out <new-dir> --metadata <environment.json> --run-id <id>

`--out` must not exist yet. `--metadata` is the environment file written by
`tools/validator` (`validator environment ...`); `--schema` and `--validator`
default to that directory's `schema.json` and built executable. `--seeds` reuses recorded root seeds. A negative control
with no keys is recorded unless `--negative-controls=false`.

Runtimes are read with `time.Now`. On Windows, setting
`DATASEAL_TIMING_CLOCK=qpc` selects the QueryPerformanceCounter, which the
stored run used.

## Records

Each line of `trials.jsonl` holds the expected and actual output, acceptance,
whether the output is wrong, the error magnitude (largest centered difference
over F_65537), operation counts, the provisioned and used keys, and stage
timings. The attack time covers only the attack function, including the
encoding of its masks, and excludes honest evaluation, decryption, and
verification.
