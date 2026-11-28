#!/usr/bin/env bash
# Fetches the pinned VERITAS checkout, builds the record validator, then builds,
# vets and tests the Go module. --no-test stops after go build and go vet.
set -euo pipefail
RUN_TESTS=1
for arg in "$@"; do
  case "$arg" in
    --no-test) RUN_TESTS=0 ;;
    *) echo "usage: $0 [--no-test]" >&2; exit 2 ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "go: $(go version)"

if [ ! -d external/veritas ]; then
  git clone https://github.com/ldsec/veritas external/veritas
  git -C external/veritas checkout 6e58ab505f81c03c1b71ffaf0dc29205293ba15a
fi

# Record validator used by both collectors and by some tests.
EXE=validator
case "$(go env GOOS)" in windows) EXE=validator.exe ;; esac
( cd tools/validator && go build -o "$EXE" . )
if [ "$RUN_TESTS" = 1 ]; then ( cd tools/validator && go test ./... ); fi

cd experiments/lattigo
go build ./...
go vet ./...
if [ "$RUN_TESTS" = 1 ]; then
  go test -timeout 60m ./...
else
  echo "tests skipped (--no-test)"
fi
