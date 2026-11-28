# Aggregates attack results into attack_counts.csv, attack_timing.csv, and attack_error.csv.
# Includes only non-warmup trials, without outlier removal.
# Timing uses one sample per execution.
# Quantiles use linear interpolation at h=(N-1)p; IQR = Q3 - Q1.
param(
    [Parameter(Mandatory = $true)][string]$Run,
    [string]$OutDir = $Run
)
$ErrorActionPreference = 'Stop'
$counts = Join-Path $OutDir 'attack_counts.csv'
$timing = Join-Path $OutDir 'attack_timing.csv'
$errors = Join-Path $OutDir 'attack_error.csv'
foreach ($f in $counts, $timing, $errors) { if (Test-Path $f) { throw "refusing to overwrite $f" } }

function Q([double[]]$xs, [double]$p) {
    $s = [double[]]($xs | Sort-Object)
    $h = ($s.Count - 1) * $p
    $lo = [math]::Floor($h); $hi = [math]::Min($lo + 1, $s.Count - 1)
    return $s[$lo] + ($h - $lo) * ($s[$hi] - $s[$lo])
}

$path = Join-Path $Run 'trials.jsonl'
$all = @(Get-Content $path -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
$main = @($all | Where-Object { -not $_.is_warmup })
$attackOrder = 'selective_scaling', 'matmul_kernel', 'addition_kernel', 'square_permute', 'square_rescale', 'missing_key_control', 'square_zero_product'
$profileOrder = 'composite', 'matmul_only', 'squaring_only', 'addition_only', 'direct_index', 'negative_control', 'not_applicable'
function Shape($r) { if ($r.input_dimensions.n) { "n=$($r.input_dimensions.n),dim=$($r.input_dimensions.padded_dim)" } else { 'none' } }
function SortKey($g) { '{0:D2}|{1}|{2:D2}|{3}' -f [array]::IndexOf($attackOrder, $g.attack), $g.shape, [array]::IndexOf($profileOrder, $g.profile), $g.verifier }

# Records per attack x shape x profile x verifier.
$countRows = foreach ($g in $main | Group-Object { "$($_.workload)|$(Shape $_)|$($_.internal_evaluation_key_profile)|$($_.verifier)" }) {
    $r0 = $g.Group[0]
    $done = @($g.Group | Where-Object execution_status -eq 'completed')
    $notRun = @($g.Group | Where-Object execution_status -ne 'completed')
    $stopped = @($notRun | ForEach-Object { if ($_.incomplete_timing_stage) { "$($_.execution_status):$($_.incomplete_timing_stage)" } else { "$($_.execution_status)" } } | Sort-Object -Unique)
    [pscustomobject][ordered]@{
        attack = $r0.workload; shape = (Shape $r0); profile = $r0.internal_evaluation_key_profile; verifier = $r0.verifier
        records = $g.Count; completed = $done.Count; not_executed = $notRun.Count; stopped_at = ($stopped -join ';')
        honest_correct = @($done | Where-Object { $_.honest_correct -eq $true }).Count
        wrong_output = @($done | Where-Object { $_.wrong_output -eq $true }).Count
        accepted = @($done | Where-Object { $_.accepted -eq $true }).Count
        attack_success = @($done | Where-Object { $_.attack_success -eq $true }).Count
    }
}
$countRows | Sort-Object { SortKey $_ } | Export-Csv -NoTypeInformation -Encoding utf8 $counts

# One sample per completed execution.
$exec = @($main | Where-Object execution_status -eq 'completed' | Group-Object paired_ciphertext_id | ForEach-Object { $_.Group[0] })
$timeRows = @(); $errRows = @()
foreach ($g in $exec | Group-Object { "$($_.workload)|$(Shape $_)|$($_.internal_evaluation_key_profile)" }) {
    $r0 = $g.Group[0]
    $key = [ordered]@{ attack = $r0.workload; shape = (Shape $r0); profile = $r0.internal_evaluation_key_profile; verifier = ''; executions = $g.Count }
    $t = [double[]]@($g.Group | ForEach-Object { [double]$_.evaluation_time_ns })
    $q1, $md, $q3 = (Q $t 0.25), (Q $t 0.5), (Q $t 0.75)
    $timeRows += [pscustomobject]($key + [ordered]@{
            evaluation_median_ms = [math]::Round($md / 1e6, 2); evaluation_q1_ms = [math]::Round($q1 / 1e6, 2); evaluation_q3_ms = [math]::Round($q3 / 1e6, 2)
            evaluation_iqr_ms = [math]::Round(($q3 - $q1) / 1e6, 2)
            evaluation_min_ms = [math]::Round(($t | Measure-Object -Minimum).Minimum / 1e6, 2); evaluation_max_ms = [math]::Round(($t | Measure-Object -Maximum).Maximum / 1e6, 2)
            rotation_count = (@($g.Group | ForEach-Object { $_.rotation_count } | Sort-Object -Unique) -join ';')
        })
    $e = [double[]]@($g.Group | ForEach-Object { [double]$_.error_magnitude })
    $changed = @($g.Group | ForEach-Object { [int]$_.changed_entry_count })
    $errRows += [pscustomobject]($key + [ordered]@{
            error_median = (Q $e 0.5); error_min = ($e | Measure-Object -Minimum).Minimum; error_max = ($e | Measure-Object -Maximum).Maximum
            changed_entries_min = ($changed | Measure-Object -Minimum).Minimum; changed_entries_max = ($changed | Measure-Object -Maximum).Maximum
            wrong_output = @($g.Group | Where-Object { $_.wrong_output -eq $true }).Count
        })
}
$timeRows | Sort-Object { SortKey $_ } | Select-Object * -ExcludeProperty verifier | Export-Csv -NoTypeInformation -Encoding utf8 $timing
$errRows | Sort-Object { SortKey $_ } | Select-Object * -ExcludeProperty verifier | Export-Csv -NoTypeInformation -Encoding utf8 $errors
Write-Output "main records=$($main.Count) executions=$($exec.Count) count rows=$(@($countRows).Count) timing rows=$($timeRows.Count)"
