# Aggregates main1 or main2 results into summary_long.csv and summary_wide.csv.
# Includes only completed, gate-passed non-warmup trials, without outlier removal.
# Quantiles use linear interpolation at h=(N-1)p; IQR = Q3 - Q1.
# Each cell is aggregated independently.
param(
    [Parameter(Mandatory = $true)][string]$Campaign,
    [string]$OutDir = $Campaign,
    [string]$Filter = 'main*-*',
    [string]$Suffix = ''
)
$ErrorActionPreference = 'Stop'
$long = Join-Path $OutDir "summary_long$Suffix.csv"
$wide = Join-Path $OutDir "summary_wide$Suffix.csv"
foreach ($f in $long, $wide) { if (Test-Path $f) { throw "refusing to overwrite $f" } }

function Q([double[]]$xs, [double]$p) {
    $s = $xs | Sort-Object
    $h = ($s.Count - 1) * $p
    $lo = [math]::Floor($h)
    $hi = [math]::Min($lo + 1, $s.Count - 1)
    return $s[$lo] + ($h - $lo) * ($s[$hi] - $s[$lo])
}

$stages = 'context_setup', 'session_key_generation', 'authentication_preparation', 'public_program_preparation', 'input_encode_encrypt', 'server_evaluation', 'verifier_precomputation', 'decryption', 'verification_decode'
$metrics = 'fair_e2e_ns', 'fair_client_ns', 'setup_ns', 'prep_ns', 'client_online_ns', 'server_ns', 'fair_gap_ns', 'direct_computation_ns', 'e2e_from_keygen_ns'
$longRows = @()
$wideRows = @()
foreach ($dir in Get-ChildItem $Campaign -Directory | Where-Object Name -like $Filter | Where-Object Name -notlike '*-aborted-*' | Sort-Object Name) {
    $path = Join-Path $dir.FullName 'trials.jsonl'
    $all = @(Get-Content $path -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    $main = @($all | Where-Object { -not $_.is_warmup })
    $ok = @($main | Where-Object { $_.execution_status -eq 'completed' -and $_.fair_timing_gate.passed -eq $true })
    if ($ok.Count -ne $main.Count) { throw "$($dir.Name): $($main.Count - $ok.Count) main trial(s) not completed/gate-passed" }
    $r0 = $ok[0]
    $key = [ordered]@{ method = $r0.implementation; packing = $r0.packing_mode; n = $r0.input_dimensions.n; profile = $r0.parameter_profile; packing_strategy = $r0.packing_strategy; stride = $r0.packing_stride; input_tiles = $r0.input_tiles; n_main = $ok.Count; n_warmup = @($all | Where-Object { $_.is_warmup }).Count }
    $series = @{}
    foreach ($m in $metrics) { $series[$m] = [double[]]@($ok | ForEach-Object { [double]$_.$m }) }
    foreach ($s in $stages) {
        $vals = @($ok | ForEach-Object { ($_.fair_timing.stages | Where-Object name -eq $s) } | Where-Object status -eq 'measured' | ForEach-Object { [double]$_.duration_ns })
        if ($vals.Count -eq $ok.Count) { $series["stage_$s`_ns"] = [double[]]$vals }
    }
    $series['ratio_client_online_over_direct'] = [double[]]@($ok | ForEach-Object { [double]$_.client_online_ns / [double]$_.direct_computation_ns })
    foreach ($name in $series.Keys) {
        $x = $series[$name]
        $q1, $med, $q3 = (Q $x 0.25), (Q $x 0.5), (Q $x 0.75)
        $longRows += [pscustomobject]([ordered]@{} + $key + [ordered]@{ metric = $name; samples = $x.Count; median = $med; q1 = $q1; q3 = $q3; iqr = $q3 - $q1; min = ($x | Measure-Object -Minimum).Minimum; max = ($x | Measure-Object -Maximum).Maximum; raw_source = $path; trial_ids = (($ok | ForEach-Object trial_id) -join ';') })
    }
    $med = @{}; $iqr = @{}
    foreach ($m in $metrics) { $med[$m] = Q $series[$m] 0.5; $iqr[$m] = (Q $series[$m] 0.75) - (Q $series[$m] 0.25) }
    $w = [ordered]@{} + $key
    foreach ($m in 'fair_e2e_ns', 'setup_ns', 'prep_ns', 'client_online_ns', 'server_ns', 'fair_client_ns') {
        $w["$($m -replace '_ns$','')_median_ms"] = [math]::Round($med[$m] / 1e6, 4)
        $w["$($m -replace '_ns$','')_iqr_ms"] = [math]::Round($iqr[$m] / 1e6, 4)
    }
    $w.direct_median_us = [math]::Round($med['direct_computation_ns'] / 1e3, 3)
    $w.direct_iqr_us = [math]::Round($iqr['direct_computation_ns'] / 1e3, 3)
    $w.gap_median_us = [math]::Round($med['fair_gap_ns'] / 1e3, 1)
    $w.ratio_online_over_direct_of_medians = [math]::Round($med['client_online_ns'] / $med['direct_computation_ns'], 1)
    $w.ratio_online_over_direct_median_of_trials = [math]::Round((Q $series['ratio_client_online_over_direct'] 0.5), 1)
    $w.accepted_all = (@($ok | Where-Object { $_.verifier -ne 'none' -and $_.accepted -ne $true }).Count -eq 0)
    $w.wrong_output_any = (@($ok | Where-Object { $_.wrong_output -ne $false }).Count -gt 0)
    $w.raw_source = $path
    $wideRows += [pscustomobject]$w
}
$longRows | Export-Csv -NoTypeInformation -Encoding utf8 $long
$wideRows | Export-Csv -NoTypeInformation -Encoding utf8 $wide
Write-Output "aggregated cells=$($wideRows.Count) long_rows=$($longRows.Count)"
