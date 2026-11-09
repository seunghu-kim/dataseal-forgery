# DataSeal verification study — research artifact

Research artifact studying verification failures in **DataSeal** (an ABFT-style
verifiable FHE scheme) and a **private-sketch linear repair** for its linear
functionality. The final evaluated homomorphic implementation is **Go + the
Lattigo v2 BFV backend pinned by the upstream VERITAS project**. A C++/OpenFHE
implementation is retained as a read-only correctness reference, not a final
benchmark backend.

> This README states only what is implemented and measured. Cryptographic HE
> bit-security is **not** asserted here; see `docs/security_parameters.md` for
> its status (estimator-dependent).

## Scientific scope

- **Ciphertext-level cryptanalysis (main contribution):** transformations a
  server can apply to encrypted, checksum-encoded matrices so that a DataSeal
  verifier accepts an output that is wrong (`accepted && wrong_output`). Each
  trial is classified by the evaluation-key capability it requires
  (`honest_minimal` vs `extended`); see `reports/ciphertext_attack_evaluation.md`.
- **Private-sketch repair:** a client-only sketch key `K (r×n)` that verifies
  the *linear* (public-right-matmul / affine) functionality DataSeal gets wrong;
  demonstrated with composition `(A·B1 + D)·B2`. No general nonlinear repair is
  claimed.
- **Performance:** public-right matrix multiplication `A(n×d)·B(d×ell)` with `A`
  confidential and `B` public, compared across FHE-only, DataSeal
  Original/Strengthened, private-sketch, and official VERITAS REP/PE.
  Addition and pointwise squaring are also supported.

## Layout

```
experiments/lattigo/        Go module `dsfgo` (final implementation)
  field, matrix             F_p reference arithmetic
  dataseal                  DataSeal encoders/verifiers (original/strengthened/appendix, add, corrected squaring)
  sketch                    private-sketch key K, register, program, prepare, verify
  bfvpack                   BFV row-major packing, public-right matmul (prepare/server split), tiling, capacity planner
  attacks                   ciphertext-level transformations (server-visible ops only)
  veritas                   adapters over official VERITAS REP (vche_1) / PE (vche_2)
  cmd/                      planreport, parammanifest, finaleval (F5 bench), attackeval (F4), bench/finalbench (historical)
include/, src/, tests/      C++/OpenFHE read-only reference + ctest suite
configs/                    pinned dependency / parameter locks
scripts/                    reproducibility scripts
docs/, reports/, results/   analysis, methodology audits, raw machine-readable data (git-ignored; regenerate with scripts/)
```

## Environment & pins

- Go 1.21+ (tested go1.23.4 darwin/arm64).
- Lattigo pinned via `experiments/lattigo/go.mod`:
  `github.com/ldsec/lattigo/v2 v2.2.1-0.20210923173451-d9eb44f2c43f`.
- Official VERITAS is an **external pinned checkout** (not vendored):
  ```
  git clone https://github.com/ldsec/veritas external/veritas
  git -C external/veritas checkout 6e58ab505f81c03c1b71ffaf0dc29205293ba15a
  ```
  `experiments/lattigo/go.mod` re-declares the same Lattigo `replace` and maps
  `veritas/vche => ../../external/veritas`. Upstream VERITAS is used unmodified.
- C++ reference needs OpenFHE 1.6.1 + CMake (optional; only for the ctest
  reference).
- Lattice-estimator (Task A, optional): `malb/lattice-estimator` under SageMath;
  see `docs/security_parameters.md`.

## Quick smoke test (deterministic, small)

```
cd experiments/lattigo
go build ./... && go vet ./...
go test ./dataseal/ ./sketch/ ./field/ ./matrix/        # fast F_p + protocol checks
go test ./veritas/ -run TestRepMatmulAuthenticated       # official REP verification
go run ./cmd/parammanifest /tmp/param_manifest.json      # actual pinned BFV parameters
```

`go test ./bfvpack/` includes the 128-size round-trips and is slower (minutes);
it is the opt-in large path.

## Reproduce the final experiments

```
bash scripts/run_final_evaluation.sh      # env capture, C++ ctest, go test, manifest, attackeval, finaleval
# HE security estimate (manual, needs SageMath):
sage results/security/estimate_security.sage results/security/param_manifest.json
```

Outputs land under `results/` (git-ignored); each raw snapshot is regenerated
from the committed code by the scripts above.

## Reading the results

- `accepted && wrong_output` = a forged result the verifier accepted.
- `honest_minimal` = only the evaluation keys the honest function distributes;
  `extended` = additional relinearization/rotation keys. A forgery that needs
  `extended` keys is **not** a direct attack under honest outsourcing.
- Comparability flags: `PASS` (matched & verified), `PARAMETER_MISMATCH`
  (different HE profile, e.g. REP/PE PN13 vs the PN14 group — absolute times not
  comparable), `METHOD_MISMATCH` (operation not implemented as a matched unit),
  `NOT_SECURITY_MATCHED` (different authentication models).
- Timing boundaries: `server_eval` is server-only ciphertext work;
  `program_prep` is public-program (mask/expected-value) preparation;
  client cost = input_prep + program_prep + decrypt + verification (see
  `reports/final_benchmark_methodology_audit.md`).

## Boundaries (important)

- **FHE-only is not authenticated** — it has no verifier; it is a correctness/
  performance baseline, reported with `accepted = N/A`, never in an acceptance
  table.
- Comparable HE confidentiality does **not** imply equal authentication
  soundness. DataSeal, private-sketch, REP, and PE use different authentication
  models.
- VERITAS REP/PE run at their native PN13 parameters; their absolute timings are
  **not** comparable to the PN14 BFV group.
- The full client cost includes preprocessing + decryption + verification, not
  verification alone.
- Private-sketch soundness `Pr[Forge] ≤ min(1, Q_auth · p^{-r})` is an analytic
  bound under the paper's model, not a timing result; `r=1` is not `r=10`.

See `LICENSE` for this artifact; upstream VERITAS keeps its own license under
`external/veritas`.
