#!/usr/bin/env bash
# Reproducible final validation + evaluation pipeline (F6). Pinned dependencies,
# fixed parameters, non-secret seeds. Captures environment, runs all tests and
# the operation-count assertion, the C++ regression, the corrected benchmark,
# the parameter manifest, and the attack-capability evaluation. Does NOT run the
# lattice-estimator (requires Sage); see results/security/ for the pinned script.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 0. Environment capture.
mkdir -p results/env
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -srm)"
  echo "go: $(go version 2>/dev/null || echo 'go missing')"
  echo "cmake: $(cmake --version 2>/dev/null | head -1 || echo 'cmake missing')"
  echo "sage: $(command -v sage >/dev/null && sage --version || echo 'NOT installed (HE bit-security UNVERIFIED)')"
} > results/env/environment.txt
cat results/env/environment.txt

# 1. Pinned VERITAS checkout (untouched upstream).
if [ ! -d external/veritas ]; then
  git clone https://github.com/ldsec/veritas external/veritas
  git -C external/veritas checkout 6e58ab505f81c03c1b71ffaf0dc29205293ba15a
fi

# 2. C++ reference regression (read-only math/test reference).
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDSF_WITH_OPENFHE=ON >/dev/null
cmake --build build -j8 >/dev/null
( cd build && ctest --output-on-failure )

# 3. Go: build, vet, gofmt check (authored packages), full tests incl op-count assertion.
cd experiments/lattigo
export GOFLAGS=-mod=mod
go build ./...
go vet ./...
# gofmt check: pre-existing dataseal.go/matrix.go keep original style (documented).
test -z "$(gofmt -l bfvpack veritas cmd sketch attacks field | grep -v -e 'dataseal/dataseal.go' -e 'matrix/matrix.go' || true)"
go test ./...

# 4. Parameter manifest (actual pinned primes) + G7 feasibility plan.
go run ./cmd/parammanifest ../../results/security/param_manifest.json
go run ./cmd/planreport ../../results/lattigo/final/feasibility.json ../../docs/lattigo_128_feasibility.md

# 5. Ciphertext attack capability evaluation (F4).
go run ./cmd/attackeval ../../results/attacks_final

# 6. Corrected performance benchmark (F5). Large sizes use a reduced, recorded
#    trial budget. Historical G9 output in results/lattigo/final/ is preserved.
GOMAXPROCS=1 go run ./cmd/finaleval ../../results/lattigo/final_v2

# 7. Lattice-estimator (MANUAL, requires Sage; not run here):
#    see results/security/estimate_security.sage and reports/security_parameters.md
echo "done. HE bit-security remains UNVERIFIED until the Sage estimator is run."
