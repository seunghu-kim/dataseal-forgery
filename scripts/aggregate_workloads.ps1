# Aggregates elementwise, input-reuse, and composition results.
# Includes only completed, gate-passed non-warmup trials, without outlier removal.
# Quantiles use linear interpolation at h=(N-1)p; IQR = Q3 - Q1.
# Per-program E2E is calculated before aggregation.
param(
    [Parameter(Mandatory = $true)][string]$Campaign,
    [string]$OutDir = $Campaign
)
$ErrorActionPreference = 'Stop'
$wide = Join-Path $OutDir 'phase3_summary_wide.csv'
$long = Join-Path $OutDir 'phase3_summary_long.csv'
$unsup = Join-Path $OutDir 'phase3_unsupported.csv'
$ratio = Join-Path $OutDir 'phase3_reuse_k8_over_k1.csv'
foreach ($f in $wide, $long, $unsup, $ratio) { if (Test-Path $f) { throw "refusing to overwrite $f" } }

function Q([double[]]$xs, [double]$p) {
    $s = [double[]]($xs | Sort-Object)
    $h = ($s.Count - 1) * $p
    $lo = [math]::Floor($h); $hi = [math]::Min($lo + 1, $s.Count - 1)
    return $s[$lo] + ($h - $lo) * ($s[$hi] - $s[$lo])
}
$metrics = 'fair_e2e_ns', 'setup_ns', 'prep_ns', 'client_online_ns', 'server_ns', 'fair_client_ns', 'fair_gap_ns', 'direct_computation_ns', 'e2e_from_keygen_ns', 'e2e_per_program_ns', 'server_per_program_ns'
$wideRows = @(); $longRows = @(); $unsupRows = @()
foreach ($dir in Get-ChildItem $Campaign -Directory | Where-Object Name -like 'p3-*' | Where-Object Name -notlike '*-aborted-*' | Sort-Object Name) {
    $path = Join-Path $dir.FullName 'trials.jsonl'
    $all = @(Get-Content $path -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    $main = @($all | Where-Object { -not $_.is_warmup })
    $parts = $dir.Name -split '-'
    $workload = $parts[1]; if ($dir.Name -like 'p3-element-*') { $workload = 'element-' + $parts[2] }
    $r0 = $main[0]
    $k = if ($workload -like 'reuse*') { [int]($workload -replace 'reuse', '') } else { 1 }
    $key = [ordered]@{ workload = ($workload -replace '\d+$', ''); method = $r0.implementation; packing = $r0.packing_mode; n = $r0.input_dimensions.n; programs = $k; n_main = $main.Count; n_warmup = $all.Count - $main.Count }
    $uns = @($all | Where-Object execution_status -eq 'unsupported_configuration')
    if ($uns.Count -gt 0) {
        if ($uns.Count -ne $all.Count) { throw "$($dir.Name): mixed unsupported/other records" }
        $unsupRows += [pscustomobject]([ordered]@{} + $key + [ordered]@{ records = $all.Count; reason = $r0.error_message; raw_source = $path })
        continue
    }
    $ok = @($main | Where-Object { $_.execution_status -eq 'completed' -and $_.fair_timing_gate.passed -eq $true })
    if ($ok.Count -ne $main.Count) { throw "$($dir.Name): $($main.Count - $ok.Count) main trial(s) not completed/gate-passed" }
    $series = @{}
    foreach ($m in $metrics) {
        if ($m -eq 'e2e_per_program_ns') { $series[$m] = [double[]]@($ok | ForEach-Object { [double]$_.fair_e2e_ns / $k }); continue }
        if ($m -eq 'server_per_program_ns') { $series[$m] = [double[]]@($ok | ForEach-Object { [double]$_.server_ns / $k }); continue }
        $series[$m] = [double[]]@($ok | ForEach-Object { [double]$_.$m })
    }
    $med = @{}; $iqr = @{}
    foreach ($m in $metrics) {
        $x = $series[$m]; $q1, $md, $q3 = (Q $x 0.25), (Q $x 0.5), (Q $x 0.75)
        $med[$m] = $md; $iqr[$m] = $q3 - $q1
        $longRows += [pscustomobject]([ordered]@{} + $key + [ordered]@{ metric = $m; samples = $x.Count; median = $md; q1 = $q1; q3 = $q3; iqr = $q3 - $q1; min = ($x | Measure-Object -Minimum).Minimum; max = ($x | Measure-Object -Maximum).Maximum; raw_source = $path })
    }
    $w = [ordered]@{} + $key
    foreach ($m in 'fair_e2e_ns', 'e2e_per_program_ns', 'server_ns', 'server_per_program_ns', 'setup_ns', 'prep_ns', 'client_online_ns') {
        $b = $m -replace '_ns$', ''
        $w["${b}_median_ms"] = [math]::Round($med[$m] / 1e6, 4); $w["${b}_iqr_ms"] = [math]::Round($iqr[$m] / 1e6, 4)
    }
    $w.direct_median_us = [math]::Round($med['direct_computation_ns'] / 1e3, 3)
    $w.direct_iqr_us = [math]::Round($iqr['direct_computation_ns'] / 1e3, 3)
    $w.gap_median_us = [math]::Round($med['fair_gap_ns'] / 1e3, 1)
    $w.verifier = $r0.verifier
    $w.wrong_output_any = (@($ok | Where-Object { $_.wrong_output -ne $false }).Count -gt 0)
    $w.accepted_all = if ($r0.verifier -eq 'none') { 'no_verifier' } else { (@($ok | Where-Object { $_.accepted -ne $true }).Count -eq 0) }
    $w.raw_source = $path
    $wideRows += [pscustomobject]$w
}
$ratioRows = @()
foreach ($g in $wideRows | Where-Object workload -eq 'reuse' | Group-Object method, packing, n) {
    $k1 = $g.Group | Where-Object programs -eq 1; $k8 = $g.Group | Where-Object programs -eq 8
    $ratioRows += [pscustomobject][ordered]@{ method = $k1.method; packing = $k1.packing; n = $k1.n; per_program_e2e_k1_ms = $k1.e2e_per_program_median_ms; per_program_e2e_k8_ms = $k8.e2e_per_program_median_ms; ratio_k8_over_k1 = [math]::Round($k8.e2e_per_program_median_ms / $k1.e2e_per_program_median_ms, 4) }
}
$wideRows | Export-Csv -NoTypeInformation -Encoding utf8 $wide
$longRows | Export-Csv -NoTypeInformation -Encoding utf8 $long
$unsupRows | Export-Csv -NoTypeInformation -Encoding utf8 $unsup
$ratioRows | Export-Csv -NoTypeInformation -Encoding utf8 $ratio
"completed cells=$($wideRows.Count) unsupported cells=$($unsupRows.Count)"
