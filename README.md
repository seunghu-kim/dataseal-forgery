# DataSeal Attack and Efficiency Experiments

This repository contains the experimental implementation of ciphertext-level attacks on DataSeal and an efficiency comparison of BFV, DataSeal, the modified scheme, and VERITAS. All implementations are written in Go using Lattigo v2 with the BFV scheme.

## Requirements

- Go 1.21 or later (Go 1.27.3 used for the reported experiments)
- Windows 10 and PowerShell for experiments
- Git Bash for building and testing on Windows
- Network access for dependency installation

Linux and macOS are supported for building and testing.

## Build and Test

```bash
bash scripts/build_and_test.sh
```

This script retrieves the pinned VERITAS implementation, builds the experiment tools, and runs the tests.

To build without running tests:

```bash
bash scripts/build_and_test.sh --no-test
```

## Repository Structure

| Path | Description |
|---|---|
| `experiments/lattigo/field` | Finite-field arithmetic |
| `experiments/lattigo/matrix` | Plaintext matrix operations |
| `experiments/lattigo/dataseal` | DataSeal encoding and verification |
| `experiments/lattigo/sketch` | Modified scheme |
| `experiments/lattigo/attacks` | Ciphertext-level attacks |
| `experiments/lattigo/bfvpack` | BFV packing and matrix operations |
| `experiments/lattigo/veritas` | VERITAS PE and REP implementations |
| `experiments/lattigo/attackrun` | Attack experiment pipeline |
| `experiments/lattigo/cmd` | Experiment entry points |
| `tools/validator` | Experiment record validation |
| `scripts` | Build, execution, and aggregation scripts |
| `configs` | Dependency and parameter configurations |
| `results` | Experimental results |

## Reproducing the Experiments

Run the following commands from the repository root in PowerShell. Use new output directories for each experiment.

### Attack Analysis

```powershell
.\scripts\run_attack.ps1 -Out out\attack
.\scripts\aggregate_attack.ps1 -Run out\attack
```

### Efficiency Analysis

```powershell
.\scripts\run_efficiency.ps1 -Campaign main1 -Out out\main1
.\scripts\run_efficiency.ps1 -Campaign main2 -Out out\main2

.\scripts\aggregate_matmul.ps1 -Campaign out\main1
.\scripts\aggregate_matmul.ps1 -Campaign out\main2

.\scripts\combine_matmul.ps1 -Phase1 out\main1\summary_wide.csv -Phase2 out\main2\summary_wide.csv -OutDir out

.\scripts\figure2_data.ps1 -Main1 out\main1 -Main2 out\main2 -OutDir out
```

`main1` covers n = 8, 16, 32, and `main2` covers n = 64, 128. Interrupted campaigns can be resumed with `-Resume`.

### Composition and Additional Workloads

```powershell
.\scripts\run_efficiency.ps1 -Campaign workloads -Out out\workloads
.\scripts\aggregate_workloads.ps1 -Campaign out\workloads
```

### Comparison with a Single Secret Vector (r = 1)

```powershell
.\scripts\run_efficiency.ps1 -Campaign sketch-r1 -Out out\sketch-r1
.\scripts\aggregate_sketch_r1.ps1 -Campaign out\sketch-r1 -Main1 out\main1 -Main2 out\main2
```

The r = 1 experiments intentionally do not satisfy the validator's r = 10 requirement.

## Experimental Results

The `results/` directory contains raw measurements, experimental configurations, environment records, validation reports, and aggregated results.

The reported experiments were conducted on an AMD Ryzen 5 2600 machine with 16 GB of RAM running Windows 10. Attack computations run serially, and efficiency experiments use `GOMAXPROCS=1`.

User and host names in the stored records were anonymized, and two descriptive note strings were translated into English. Consequently, some recorded file hashes no longer match. No measured values were changed.

## License

See `LICENSE`. VERITAS retains its original license.