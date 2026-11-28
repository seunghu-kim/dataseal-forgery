# Extracts client-side verification and direct computation times (ms)
# from the main1 and main2 summaries using controlled packing.
# Preparation + verification is the sum of their respective medians.
param(
    [Parameter(Mandatory = $true)][string]$Main1,
    [Parameter(Mandatory = $true)][string]$Main2,
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$out = Join-Path $OutDir 'figure2_data.csv'
if (Test-Path $out) { throw "refusing to overwrite $out" }

$inv = [Globalization.CultureInfo]::InvariantCulture
$rows = @()
foreach ($d in $Main1, $Main2) { $rows += Import-Csv (Join-Path $d 'summary_long.csv') | Where-Object packing -eq 'controlled' }
function Med($method, $n, $metric) {
    $r = @($rows | Where-Object { $_.method -eq $method -and [int]$_.n -eq $n -and $_.metric -eq $metric })
    if ($r.Count -ne 1) { throw "expected one row for $method n=$n ${metric}, found $($r.Count)" }
    return [double]::Parse($r[0].median, $inv)
}
$s3 = 'stage_authentication_preparation_ns'; $s9 = 'stage_verification_decode_ns'
$data = foreach ($n in $rows | ForEach-Object { [int]$_.n } | Sort-Object -Unique) {
    $prep = Med 'private_sketch' $n $s3
    $check = Med 'private_sketch' $n $s9
    [pscustomobject][ordered]@{
        n = $n
        direct_ms = (Med 'bfv_only' $n 'direct_computation_ns') / 1e6
        dataseal_check_ms = (Med 'dataseal_original' $n $s9) / 1e6
        modified_check_ms = $check / 1e6
        modified_prep_ms = $prep / 1e6
        modified_prep_check_ms = ($prep + $check) / 1e6
    }
}
$data | Export-Csv -NoTypeInformation -Encoding utf8 $out
Write-Output "wrote $out ($(@($data).Count) sizes)"
