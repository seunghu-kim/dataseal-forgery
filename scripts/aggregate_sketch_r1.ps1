# Compares private checksums with r=1 and r=10 against DataSeal's original checks.
# Uses sketch-r1 for r=1 and main1/main2 for r=10.
# Includes only completed, gate-passed non-warmup trials, without outlier removal.
# Quantiles use linear interpolation at h=(N-1)p; IQR = Q3 - Q1.
param(
    [Parameter(Mandatory = $true)][string]$Campaign,
    [Parameter(Mandatory = $true)][string]$Main1,
    [Parameter(Mandatory = $true)][string]$Main2,
    [string]$OutDir = $Campaign
)
$ErrorActionPreference = 'Stop'
$campaign = $Campaign
$m1 = $Main1
$m2 = $Main2
$long = Join-Path $OutDir 'summary_long.csv'
$cmp = Join-Path $OutDir 'comparison.csv'
foreach ($f in $long, $cmp) { if (Test-Path $f) { throw "refusing to overwrite $f" } }

function Q([double[]]$xs, [double]$p) {
    $s = $xs | Sort-Object
    $h = ($s.Count - 1) * $p
    $lo = [math]::Floor($h)
    $hi = [math]::Min($lo + 1, $s.Count - 1)
    return $s[$lo] + ($h - $lo) * ($s[$hi] - $s[$lo])
}
$stageMetric = [ordered]@{ S3 = 'authentication_preparation'; S6 = 'server_evaluation'; S9 = 'verification_decode' }

$sources = @()
foreach ($n in 8, 16, 32, 64, 128) {
    $old = if ($n -le 32) { @($m1, 'main1') } else { @($m2, 'main2') }
    $sources += , @('sketch_r1', $n, (Join-Path $campaign "main-private_sketch_r1-controlled-n$n"))
    $sources += , @('dataseal_new', $n, (Join-Path $campaign "main-dataseal_original-controlled-n$n"))
    $sources += , @('sketch_r10', $n, (Join-Path $old[0] ("{0}-private_sketch-controlled-n{1}" -f $old[1], $n)))
    $sources += , @('dataseal_old', $n, (Join-Path $old[0] ("{0}-dataseal_original-controlled-n{1}" -f $old[1], $n)))
}

$rows = @()
foreach ($s in $sources) {
    $src, $n, $dir = $s
    $path = Join-Path $dir 'trials.jsonl'
    $all = @(Get-Content $path -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    $main = @($all | Where-Object { -not $_.is_warmup })
    $ok = @($main | Where-Object { $_.execution_status -eq 'completed' -and $_.fair_timing_gate.passed -eq $true })
    if ($ok.Count -ne $main.Count) { throw "${dir}: $($main.Count - $ok.Count) main trial(s) not completed/gate-passed" }
    $series = [ordered]@{ E2E = [double[]]@($ok | ForEach-Object { [double]$_.fair_e2e_ns }) }
    foreach ($k in $stageMetric.Keys) {
        $vals = @($ok | ForEach-Object { ($_.fair_timing.stages | Where-Object name -eq $stageMetric[$k]) } | Where-Object status -eq 'measured' | ForEach-Object { [double]$_.duration_ns })
        if ($vals.Count -ne $ok.Count) { throw "${dir}: stage $k measured in $($vals.Count)/$($ok.Count) trials" }
        $series[$k] = [double[]]$vals
    }
    $counts = @($all | ForEach-Object { "$($_.rotation_count)/$($_.ciphertext_multiplication_count)/$($_.plaintext_multiplication_count)/$($_.addition_count)" } | Sort-Object -Unique)
    $rs = @($all | ForEach-Object { $_.sketch_r } | Sort-Object -Unique)
    $acc = @($main | Where-Object { $_.accepted -eq $true }).Count
    $wrong = @($main | Where-Object { $_.wrong_output -ne $false }).Count
    $below = @($all | ForEach-Object { $_.security_below_target } | Sort-Object -Unique)
    foreach ($k in $series.Keys) {
        $x = $series[$k]
        $q1, $med, $q3 = (Q $x 0.25), (Q $x 0.5), (Q $x 0.75)
        $rows += [pscustomobject][ordered]@{ source = $src; n = $n; metric = $k; samples = $x.Count; median_ns = $med; q1_ns = $q1; q3_ns = $q3; iqr_ns = $q3 - $q1;
            server_counts_rot_mulct_mulpt_add = ($counts -join ';'); sketch_r = ($rs -join ';'); security_below_target = ($below -join ';'); main_accepted = "$acc/$($main.Count)"; main_wrong_output = $wrong; raw_source = $path }
    }
}
$rows | Export-Csv -NoTypeInformation -Encoding utf8 $long

function Get-R($src, $n, $m) { $rows | Where-Object { $_.source -eq $src -and $_.n -eq $n -and $_.metric -eq $m } }
$cmpRows = @()
foreach ($n in 8, 16, 32, 64, 128) {
    foreach ($m in 'E2E', 'S3', 'S6', 'S9') {
        $r1, $r10, $dn, $do = (Get-R 'sketch_r1' $n $m), (Get-R 'sketch_r10' $n $m), (Get-R 'dataseal_new' $n $m), (Get-R 'dataseal_old' $n $m)
        $cmpRows += [pscustomobject][ordered]@{ n = $n; metric = $m;
            r1_median_ns = $r1.median_ns; r1_iqr_ns = $r1.iqr_ns; dataseal_new_median_ns = $dn.median_ns; dataseal_new_iqr_ns = $dn.iqr_ns;
            r10_median_ns = $r10.median_ns; r10_iqr_ns = $r10.iqr_ns; dataseal_old_median_ns = $do.median_ns; dataseal_old_q1_ns = $do.q1_ns; dataseal_old_q3_ns = $do.q3_ns;
            ratio_r1_over_dataseal_new = $r1.median_ns / $dn.median_ns; ratio_r10_over_r1 = $r10.median_ns / $r1.median_ns;
            dataseal_new_median_within_old_iqr = ($dn.median_ns -ge $do.q1_ns -and $dn.median_ns -le $do.q3_ns);
            dataseal_new_minus_old_pct = 100 * ($dn.median_ns - $do.median_ns) / $do.median_ns;
            counts_r1 = $r1.server_counts_rot_mulct_mulpt_add; counts_r10 = $r10.server_counts_rot_mulct_mulpt_add; counts_dataseal_new = $dn.server_counts_rot_mulct_mulpt_add; counts_dataseal_old = $do.server_counts_rot_mulct_mulpt_add }
    }
}
$cmpRows | Export-Csv -NoTypeInformation -Encoding utf8 $cmp
Write-Output "wrote $long and $cmp"
