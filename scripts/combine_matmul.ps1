# Merges the main1 and main2 matrix multiplication summaries into a single table.
# Reports median [IQR] by method, packing, and matrix size, with consistency checks.
param(
    [Parameter(Mandatory = $true)][string]$Phase1,
    [Parameter(Mandatory = $true)][string]$Phase2,
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$outCombined = Join-Path $OutDir 'combined_summary_n8_n128.csv'
$outCons = Join-Path $OutDir 'consistency_main2.csv'
foreach ($f in $outCombined, $outCons) { if (Test-Path $f) { throw "refusing to overwrite $f" } }

$inv = [Globalization.CultureInfo]::InvariantCulture
function D($s) { [double]::Parse($s, $inv) }
function F($m, $i, $fmt) { '{0} [{1}]' -f (D $m).ToString($fmt, $inv), (D $i).ToString($fmt, $inv) }

$rows = @()
foreach ($p in @(@{ phase = 1; path = $Phase1 }, @{ phase = 2; path = $Phase2 })) {
    foreach ($r in Import-Csv $p.path) { $r | Add-Member phase $p.phase; $rows += $r }
}
$methodOrder = 'bfv_only', 'dataseal_original', 'dataseal_strengthened', 'private_sketch', 'veritas_pe', 'veritas_pe_t17', 'veritas_rep'
$rows = $rows | Sort-Object @{ e = { [array]::IndexOf($methodOrder, $_.method) } }, packing, @{ e = { [int]$_.n } }

$combined = foreach ($r in $rows) {
    [pscustomobject][ordered]@{
        method = $r.method; packing = $r.packing; n = [int]$r.n; phase = $r.phase
        profile = $r.profile; packing_strategy = $r.packing_strategy; input_tiles = $r.input_tiles; n_main = $r.n_main
        e2e_ms = F $r.fair_e2e_median_ms $r.fair_e2e_iqr_ms 'F2'
        setup_ms = F $r.setup_median_ms $r.setup_iqr_ms 'F2'
        prep_ms = F $r.prep_median_ms $r.prep_iqr_ms 'F2'
        client_online_ms = F $r.client_online_median_ms $r.client_online_iqr_ms 'F3'
        server_ms = F $r.server_median_ms $r.server_iqr_ms 'F2'
        direct_us = F $r.direct_median_us $r.direct_iqr_us 'F2'
        online_over_direct = $r.ratio_online_over_direct_of_medians
        accepted_all = $r.accepted_all; wrong_output_any = $r.wrong_output_any
        source_summary = $(if ($r.phase -eq 1) { $Phase1 } else { $Phase2 })
    }
}
$combined | Export-Csv -NoTypeInformation -Encoding utf8 $outCombined

$cons = @()
# 1) REP: server median / number of b x b block products, (n/b)^3 with b=8
foreach ($r in $rows | Where-Object method -eq 'veritas_rep') {
    $blocks = [math]::Pow([int]$r.n / 8, 3)
    $cons += [pscustomobject][ordered]@{ check = 'rep_server_per_block_ms'; n = [int]$r.n; group = 'veritas_rep/native'; value = [math]::Round((D $r.server_median_ms) / $blocks, 2); detail = "server_median_ms=$($r.server_median_ms) blocks=(n/8)^3=$blocks" }
}
# 2) BFV family (4 methods x 2 packings): spread of medians, (max-min)/min
$bfv = 'bfv_only', 'dataseal_original', 'dataseal_strengthened', 'private_sketch'
foreach ($n in $rows | Where-Object { $bfv -contains $_.method } | ForEach-Object { [int]$_.n } | Sort-Object -Unique) {
    foreach ($pk in 'all', 'controlled', 'native') {
        $g = @($rows | Where-Object { $bfv -contains $_.method -and [int]$_.n -eq $n -and ($pk -eq 'all' -or $_.packing -eq $pk) })
        foreach ($m in 'fair_e2e', 'server', 'fair_client', 'client_online') {
            $v = $g | ForEach-Object { D $_."$($m)_median_ms" }
            $mn = ($v | Measure-Object -Minimum).Minimum; $mx = ($v | Measure-Object -Maximum).Maximum
            $lo = ($g | Where-Object { (D $_."$($m)_median_ms") -eq $mn } | Select-Object -First 1); $hi = ($g | Where-Object { (D $_."$($m)_median_ms") -eq $mx } | Select-Object -First 1)
            $cons += [pscustomobject][ordered]@{ check = "bfv_family_spread_pct_$m"; n = $n; group = "packing=$pk cells=$($g.Count)"; value = [math]::Round(100 * ($mx - $mn) / $mn, 2); detail = "min=$mn ($($lo.method)/$($lo.packing)) max=$mx ($($hi.method)/$($hi.packing))" }
        }
    }
}
# 3) client_online / direct (ratio of medians) per method x packing x n
foreach ($r in $rows) {
    $cons += [pscustomobject][ordered]@{ check = 'online_over_direct'; n = [int]$r.n; group = "$($r.method)/$($r.packing)"; value = [math]::Round((D $r.client_online_median_ms) * 1000 / (D $r.direct_median_us), 2); detail = "client_online_median_ms=$($r.client_online_median_ms) direct_median_us=$($r.direct_median_us)" }
}
$cons | Export-Csv -NoTypeInformation -Encoding utf8 $outCons
Write-Output "combined rows=$(@($combined).Count) consistency rows=$($cons.Count)"
