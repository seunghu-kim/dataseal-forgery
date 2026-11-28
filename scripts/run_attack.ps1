# Runs ciphertext-level attacks under different evaluation key profiles.
# Timing uses the Windows QueryPerformanceCounter (QPC).
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Repo = (Split-Path $PSScriptRoot -Parent),
    [string]$RunId = ('A-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')),
    [int]$Trials = 20,
    [int]$Warmups = 1,
    [string]$Seeds = ''
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path $Repo).Path
if (Test-Path $Out) { throw "output exists, refusing: $Out" }
$parent = Split-Path $Out -Parent
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
$meta = "$Out-environment.json"
if (Test-Path $meta) { throw "metadata exists, refusing: $meta" }

$tool = Join-Path $Repo 'tools/validator/validator.exe'
if (-not (Test-Path $tool)) {
    Push-Location (Join-Path $Repo 'tools/validator')
    try { & go build -o validator.exe . ; if ($LASTEXITCODE -ne 0) { throw 'validator build failed' } } finally { Pop-Location }
}

$profiles = 'composite,squaring_only,addition_only,matmul_only,direct_index'
$args = @('--collect', '--repo', $Repo, '--out', $Out, '--metadata', $meta, '--run-id', $RunId,
    '--mode', 'independent', '--trials', "$Trials", '--warmups', "$Warmups", '--profiles', $profiles)
if ($Seeds -ne '') { $args += @('--seeds', $Seeds) }
$exact = "go 'run' '-mod=readonly' './cmd/attackeval' " + (($args | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' ')

& $tool environment --repo $Repo --command $exact `
    --boundary 'Experiment A collector boundaries in trials.jsonl; paired verifier totals exclude other verifiers' `
    --profiles 'PN14QP438' --warmups $Warmups --repetitions $Trials --out $meta | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'metadata failed' }

$oldClock = $env:DATASEAL_TIMING_CLOCK; $oldProcs = $env:GOMAXPROCS
$env:DATASEAL_TIMING_CLOCK = 'qpc'
Remove-Item Env:GOMAXPROCS -ErrorAction SilentlyContinue
Push-Location (Join-Path $Repo 'experiments/lattigo')
try {
    & go run -mod=readonly ./cmd/attackeval @args
    if ($LASTEXITCODE -ne 0) { throw "attackeval failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
    $env:DATASEAL_TIMING_CLOCK = $oldClock; $env:GOMAXPROCS = $oldProcs
}
Write-Output "wrote $Out"
