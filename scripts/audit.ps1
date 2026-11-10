$ErrorActionPreference = 'Stop'
$lock = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../Cargo.lock')
$queries = @([regex]::Matches($lock, '(?s)\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"\s*source = "registry\+[^"\r\n]+"') | ForEach-Object { @{ package = @{ name = $_.Groups[1].Value; ecosystem = 'crates.io' }; version = $_.Groups[2].Value } })
$result = Invoke-RestMethod -Uri 'https://api.osv.dev/v1/querybatch' -Method Post -ContentType 'application/json' -Body (@{queries=$queries} | ConvertTo-Json -Depth 6 -Compress)
$count = 0
if ($result.results.Count -ne $queries.Count) { throw 'Advisory service returned an incomplete result.' }
for ($i=0; $i -lt $result.results.Count; $i++) {
    if ($result.results[$i].vulns) { $count++; Write-Output "$($queries[$i].package.name) $($queries[$i].version): $($result.results[$i].vulns.id -join ', ')" }
}
Write-Output "Checked $($queries.Count) public package versions; $count packages matched advisories."
if ($count -gt 0) { throw 'Dependency advisory review required.' }
