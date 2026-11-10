$ErrorActionPreference = 'Stop'
# Check distributable working-tree files; report paths only, never matching values.
$paths = @(& git ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
$patterns = @('AKIA[0-9A-Z]{16}', 'gh[pousr]_[A-Za-z0-9]{36,}', 'github_pat_[A-Za-z0-9_]{50,}', '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', 'sk-proj-[A-Za-z0-9_-]{40,}')
$matchesFound = @()
foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    # Unix dotfiles and Windows Hidden attributes require -Force for Get-Item.
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -gt 2MB) { continue }
    $content = [IO.File]::ReadAllText($item.FullName)
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) { $matchesFound += $path; break }
    }
}
if ($matchesFound.Count) { $matchesFound | Sort-Object -Unique; throw 'Potential secrets found; review these files before publishing.' }
Write-Output "Checked $($paths.Count) working-tree paths; no supported credential patterns found. This does not inspect Git history or prove the absence of secrets."
