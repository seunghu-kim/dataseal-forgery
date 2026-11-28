# Runs efficiency experiments with GOMAXPROCS=1.
# Each cell runs in a separate process with one warmup trial.
# Default repetitions: 20 trials, or 10 for n=128.
param(
    [Parameter(Mandatory = $true)][ValidateSet('main1', 'main2', 'workloads', 'sketch-r1')][string]$Campaign,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Repo = (Split-Path $PSScriptRoot -Parent),
    [int]$Rep128Trials = 10,
    [string]$Only = '',
    [switch]$Resume
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path $Repo).Path
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out | Out-Null }
$Out = (Resolve-Path $Out).Path
$peT = '18014398507614209'
$sketchMsg = 'this reporting protocol requires p=65537, r=10, 1<=Q_auth<=2^32'
$oldProcs = $env:GOMAXPROCS; $oldFlags = $env:GOFLAGS
$env:GOMAXPROCS = '1'
$env:GOFLAGS = '-mod=readonly'

$tool = Join-Path $Repo 'tools/validator/validator.exe'
if (-not (Test-Path $tool)) {
    Push-Location (Join-Path $Repo 'tools/validator')
    try { & go build -o validator.exe . ; if ($LASTEXITCODE -ne 0) { throw 'validator build failed' } } finally { Pop-Location }
}
$exe = Join-Path $Out 'efficiencyeval.exe'
$shaFile = "$exe.sha256"
if (-not (Test-Path $exe)) {
    Push-Location (Join-Path $Repo 'experiments/lattigo')
    try { & go build -o $exe ./cmd/efficiencyeval ; if ($LASTEXITCODE -ne 0) { throw 'build failed' } } finally { Pop-Location }
    (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() | Set-Content -Encoding ascii $shaFile
} elseif ((Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() -ne (Get-Content $shaFile).Trim()) { throw 'existing efficiencyeval.exe differs from its recorded hash' }

# Cell: label, workload, method, packing, n, programs, sketch rows, trials, warmups.
function New-Cell($label, $w, $m, $p, $n, $k, $rows, $trials) {
    [pscustomobject]@{ label = $label; workload = $w; method = $m; packing = $p; n = $n; programs = $k; rows = $rows; trials = $trials; warmups = 1 }
}
$bfv = 'bfv_only', 'dataseal_original', 'dataseal_strengthened', 'private_sketch'
$all = $bfv + @('veritas_rep', 'veritas_pe')
$cells = @()
if ($Campaign -eq 'main1') {
    foreach ($n in 8, 16, 32) {
        foreach ($m in $bfv) { foreach ($p in 'controlled', 'native') { $cells += New-Cell "main1-$m-$p-n$n" 'matmul' $m $p $n 1 0 20 } }
        $cells += New-Cell "main1-veritas_rep-native-n$n" 'matmul' 'veritas_rep' 'native' $n 1 0 20
        $cells += New-Cell "main1-veritas_pe-native-n$n" 'matmul' 'veritas_pe' 'native' $n 1 0 20
        if ($n -le 16) { $cells += New-Cell "main1-veritas_pe_t17-native-n$n" 'matmul' 'veritas_pe_t17' 'native' $n 1 0 20 }
    }
}
if ($Campaign -eq 'main2') {
    foreach ($n in 64, 128) {
        $t = if ($n -eq 64) { 20 } else { 10 }
        foreach ($m in $bfv) { foreach ($p in 'controlled', 'native') { $cells += New-Cell "main2-$m-$p-n$n" 'matmul' $m $p $n 1 0 $t } }
        $cells += New-Cell "main2-veritas_pe-native-n$n" 'matmul' 'veritas_pe' 'native' $n 1 0 $t
        $rt = if ($n -eq 128) { $Rep128Trials } else { $t }
        $cells += New-Cell "main2-veritas_rep-native-n$n" 'matmul' 'veritas_rep' 'native' $n 1 0 $rt
    }
}
if ($Campaign -eq 'workloads') {
    foreach ($op in 'element-add', 'element-square') { foreach ($n in 16, 32) { foreach ($m in $all) { $cells += New-Cell "p3-$op-$m-native-n$n" $op $m 'native' $n 1 0 20 } } }
    foreach ($n in 8, 16) {
        foreach ($k in 1, 2, 4, 8) {
            foreach ($m in $bfv) { foreach ($p in 'controlled', 'native') { $cells += New-Cell "p3-reuse$k-$m-$p-n$n" 'reuse' $m $p $n $k 0 20 } }
            foreach ($m in 'veritas_rep', 'veritas_pe') { $cells += New-Cell "p3-reuse$k-$m-native-n$n" 'reuse' $m 'native' $n $k 0 20 }
        }
    }
    foreach ($n in 4, 8, 16) { foreach ($m in $all) { $cells += New-Cell "p3-compose-$m-native-n$n" 'compose' $m 'native' $n 1 0 20 } }
}
if ($Campaign -eq 'sketch-r1') {
    foreach ($n in 8, 16, 32, 64, 128) {
        $t = if ($n -eq 128) { 10 } else { 20 }
        $cells += New-Cell "main-private_sketch_r1-controlled-n$n" 'matmul' 'private_sketch' 'controlled' $n 1 1 $t
        $cells += New-Cell "main-dataseal_original-controlled-n$n" 'matmul' 'dataseal_original' 'controlled' $n 1 0 $t
    }
}
if ($Only -ne '') { $cells = @($cells | Where-Object { $_.label -match $Only }) }

# Validate completed cells, allowing only the expected r=1 validation error.
function Test-Cell($dir, $rows, $total) {
    $gf = Join-Path $dir 'fair_gates.json'
    if (-not (Test-Path $gf)) { throw "no fair_gates.json in $dir" }
    $g = Get-Content $gf -Raw | ConvertFrom-Json
    if ($g.failed -ne 0 -or $g.records -ne $total -or $g.stopped_early) { throw "gate failure in ${dir}: failed=$($g.failed) records=$($g.records)" }
    if ($g.offline_validator_ok) {
        if ($rows -gt 0) { throw "r=$rows cell unexpectedly passed the r=10 validator rule: $dir" }
        return 'pass'
    }
    if ($rows -eq 0) { throw "validator failed: $dir" }
    $v = Get-Content (Join-Path $dir 'validation.json') -Raw | ConvertFrom-Json
    $issues = @($v.issues)
    $bad = @($issues | Where-Object { $_.severity -ne 'error' -or $_.field -ne 'sketch_assumptions' -or $_.message -ne $sketchMsg })
    $perRow = @($issues | Group-Object row)
    if ($v.rows -ne $total -or $bad.Count -ne 0 -or $issues.Count -ne $total -or $perRow.Count -ne $total) {
        throw "r=$rows validator issues are not exactly one sketch_assumptions error per row in ${dir}"
    }
    return 'expected_reject_sketch_assumptions_only'
}

$wallCsv = Join-Path $Out 'process_wall.csv'
try {
foreach ($c in $cells) {
    $dir = Join-Path $Out $c.label
    $meta = Join-Path $Out ($c.label + '-environment.json')
    $log = Join-Path $Out ($c.label + '-execution.log')
    $total = $c.trials + $c.warmups
    if (Test-Path $dir) {
        if (-not $Resume) { throw "output exists, refusing: $dir (use -Resume)" }
        $done = $false
        try { $null = Test-Cell $dir $c.rows $total; $done = $true } catch { }
        if ($done) { Write-Output "skip (complete): $($c.label)"; continue }
        $suffix = '-aborted-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        foreach ($pth in @($dir, $meta, $log)) {
            if (Test-Path $pth) {
                $leaf = Split-Path $pth -Leaf; $ext = [IO.Path]::GetExtension($leaf)
                $newName = if ($ext -in '.json', '.log') { [IO.Path]::GetFileNameWithoutExtension($leaf) + $suffix + $ext } else { $leaf + $suffix }
                Rename-Item -LiteralPath $pth -NewName $newName
            }
        }
    }
    $profile = if ($c.method -eq 'veritas_pe') { 'PN14QP438-T54' } else { 'PN14QP438' }
    $cellArgs = @('--repo', $Repo, '--out', $dir, '--metadata', $meta, '--run-id', ((Split-Path $Out -Leaf) + '-' + $c.label),
        '--workload', $c.workload, '--programs', "$($c.programs)", '--sizes', "$($c.n)", '--methods', $c.method, '--packings', $c.packing,
        '--trials', "$($c.trials)", '--warmups', "$($c.warmups)", '--seed', '1', '--pe-t', $peT, '--stop-on-error')
    if ($c.rows -gt 0) { $cellArgs += @('--sketch-rows', "$($c.rows)") }
    $exact = 'GOMAXPROCS=1 efficiencyeval ' + (($cellArgs | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' ')
    & $tool environment --repo $Repo --command $exact `
        --boundary 'common S1..S9 QPC boundary; one process per cell; GOMAXPROCS=1' `
        --profiles $profile --warmups $c.warmups --repetitions $c.trials --out $meta | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "metadata failed: $($c.label)" }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ErrorActionPreference = 'Continue'   # an r=1 cell reports its expected validator failure on stderr
    & $exe @cellArgs 2>&1 | Tee-Object -FilePath $log | Out-Null
    $exit = $LASTEXITCODE; $sw.Stop()
    $ErrorActionPreference = 'Stop'
    $verdict = Test-Cell $dir $c.rows $total
    if ($exit -ne 0 -and $verdict -eq 'pass') { throw "nonzero exit with passing validator: $($c.label)" }
    [pscustomobject]@{ cell = $c.label; workload = $c.workload; method = $c.method; packing = $c.packing; n = $c.n; programs = $c.programs; sketch_rows = $c.rows; trials = $c.trials; warmups = $c.warmups; process_wall_s = [math]::Round($sw.Elapsed.TotalSeconds, 1); exit = $exit; validator = $verdict; finished_utc = [DateTime]::UtcNow.ToString('o') } |
        Export-Csv -NoTypeInformation -Encoding utf8 -Append $wallCsv
    Write-Output ("{0} {1} exit={2} validator={3} wall={4:N1}s" -f [DateTime]::UtcNow.ToString('HH:mm:ss'), $c.label, $exit, $verdict, $sw.Elapsed.TotalSeconds)
}
} finally { $env:GOMAXPROCS = $oldProcs; $env:GOFLAGS = $oldFlags }
("{0}-complete" -f $Campaign) | Add-Content (Join-Path $Out 'campaign-status.txt')
Write-Output "$Campaign complete: $($cells.Count) cell(s)"
