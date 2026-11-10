$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot 'check-secrets.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $tempRoot ('graphxploit-secret-check-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
function Invoke-Checker {
    $info = [Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $fixture
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in @('-NoProfile','-File',$checker)) { $info.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) { $process.Kill($true); throw 'Secret-check test timed out' }
    $result = @{exit=$process.ExitCode;output=$stdout.Result;error=$stderr.Result}
    $process.Dispose()
    return $result
}
try {
    & git -C $fixture init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize test repository' }
    $ignore = Join-Path $fixture '.gitignore'
    [IO.File]::WriteAllText($ignore, '*.tmp')
    if ($IsWindows) { [IO.File]::SetAttributes($ignore, [IO.FileAttributes]::Hidden) }
    $clean = Invoke-Checker
    if ($clean.exit -ne 0) { throw "Clean hidden-file check failed: $($clean.error)" }
    # Synthetic credential shape, assembled to avoid embedding a matching token.
    $canary = 'ghp_' + ('A' * 36)
    $secretPath = Join-Path $fixture '.hidden source.txt'
    [IO.File]::WriteAllText($secretPath, $canary)
    if ($IsWindows) { [IO.File]::SetAttributes($secretPath, [IO.FileAttributes]::Hidden) }
    $detected = Invoke-Checker
    if ($detected.exit -eq 0 -or -not $detected.output.Contains('.hidden source.txt')) {
        throw 'Credential-shaped content in a hidden file was not reported'
    }
    if (($detected.output + $detected.error).Contains($canary)) { throw 'Secret-check output disclosed matched content' }
    Write-Output 'Secret-check regressions passed: clean dotfile, hidden credential, paths with spaces, and output redaction.'
} finally {
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ($resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('graphxploit-secret-check-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
