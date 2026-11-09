#!/usr/bin/env bash
# Reproducible build/test/benchmark for the unified Lattigo/BFV suite.
# Prerequisites: Go (>=1.16 arm64), network for the pinned Lattigo module, and
# the VERITAS checkout under external/veritas (git clone if absent).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 1. Official VERITAS checkout (pinned commit), untouched.
if [ ! -d external/veritas ]; then
  git clone https://github.com/ldsec/veritas external/veritas
  git -C external/veritas checkout 6e58ab505f81c03c1b71ffaf0dc29205293ba15a
fi

# 2. C++ reference regression (read-only math/test reference).
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDSF_WITH_OPENFHE=ON >/dev/null
cmake --build build -j8 >/dev/null
( cd build && ctest --output-on-failure )

# 3. Go unified suite: tests, planner report (G7), G5 and G9 benchmarks.
cd experiments/lattigo
export GOFLAGS=-mod=mod
go vet ./...
go test ./...
# G7 deterministic feasibility/capacity plan (fast).
go run ./cmd/planreport ../../results/lattigo/final/feasibility.json ../../docs/lattigo_128_feasibility.md
# G5 historical benchmark (preserved).
GOMAXPROCS=1 go run ./cmd/bench ../../results/lattigo
# G9 final size sweep through 128 + VERITAS authenticated matmul + r-sweep.
# Large (128) cells use a reduced trial budget; see each cell's "trials" field.
GOMAXPROCS=1 go run ./cmd/finalbench ../../results/lattigo/final

# 4. Optional: upstream VERITAS REP/PE microbenchmarks (within-library baseline).
#    cd "$ROOT/external/veritas"
#    GOFLAGS=-mod=mod go test ./vche_1/ -bench '^BenchmarkVCHE1$' -run '^$' -benchtime=1000x -timeout 60m
#    GOFLAGS=-mod=mod go test ./vche_2/ -bench '^BenchmarkVCHE2$' -run '^$' -benchtime=1000x -timeout 60m

echo "done; raw results under results/lattigo/"
