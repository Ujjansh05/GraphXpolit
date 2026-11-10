param([string]$OutputFile = 'graphxploit.cdx.json', [switch]$Ai)
$ErrorActionPreference = 'Stop'
$targetTriple = if ($env:OS -eq 'Windows_NT') { 'x86_64-pc-windows-msvc' } else { 'x86_64-unknown-linux-gnu' }
$arguments = @('metadata','--locked','--format-version','1','--filter-platform',$targetTriple)
if ($Ai) { $arguments += @('--features','ai') }
$raw = & cargo @arguments
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
$metadata = $raw | ConvertFrom-Json
$byId = @{}; $nodes = @{}
foreach ($p in $metadata.packages) { $byId[$p.id] = $p }
foreach ($n in $metadata.resolve.nodes) { $nodes[$n.id] = $n }
$seen = @{}; $pending = New-Object 'Collections.Generic.Queue[string]'
$pending.Enqueue($metadata.resolve.root)
while ($pending.Count) {
    $id = $pending.Dequeue()
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    foreach ($dep in $nodes[$id].deps) {
        if (@($dep.dep_kinds | Where-Object { $_.kind -ne 'dev' }).Count) { $pending.Enqueue($dep.pkg) }
    }
}
$components = @($seen.Keys | ForEach-Object {
    $p = $byId[$_]
    @{type='library';name=$p.name;version=$p.version;'bom-ref'="pkg:cargo/$($p.name)@$($p.version)";purl="pkg:cargo/$($p.name)@$($p.version)"}
} | Sort-Object name,version)
$bom = @{bomFormat='CycloneDX';specVersion='1.5';version=1;metadata=@{timestamp=[DateTime]::UtcNow.ToString('o');properties=@(@{name='graphxploit:target';value=$targetTriple},@{name='graphxploit:edition';value=$(if ($Ai) {'ai'} else {'lite'})})};components=$components}
[IO.File]::WriteAllText((Join-Path (Get-Location) $OutputFile), ($bom | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
