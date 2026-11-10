param(
    [string]$Binary = (Join-Path $PSScriptRoot '../target/release/graphxploit.exe'),
    [int[]]$Files = @(100, 1000, 10000)
)
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$benchRoot = Join-Path $tempRoot ('graphxploit-bench-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($benchRoot) | Out-Null
function Measure-Scan([string]$project, [string]$data, [string]$kind, [int]$count) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $binaryPath
    $info.Arguments = '-C "' + $project + '" ix'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['GRAPHXPLOIT_DATA_DIR'] = $data
    $p = New-Object Diagnostics.Process
    $p.StartInfo = $info
    $timer = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    $peak = 0L
    while (-not $p.HasExited) {
        $p.Refresh()
        try { $peak = [Math]::Max($peak, $p.PeakWorkingSet64) } catch {}
        Start-Sleep -Milliseconds 10
    }
    $p.WaitForExit(); $timer.Stop()
    if ($p.ExitCode -ne 0) { throw $stderr.Result }
    $bytes = (Get-ChildItem -LiteralPath $data -Recurse -File | Measure-Object -Property Length -Sum).Sum
    [pscustomobject]@{files=$count;operation=$kind;milliseconds=[Math]::Round($timer.Elapsed.TotalMilliseconds,2);sampled_peak_working_set_bytes=$peak;index_bytes=$bytes;binary_bytes=(Get-Item -LiteralPath $binaryPath).Length;summary=$stdout.Result.Trim()}
    $p.Dispose()
}
try {
    foreach ($count in $Files) {
        if ($count -lt 1 -or $count -gt 10000) { throw 'Fixture size must be 1..10000.' }
        $project = Join-Path $benchRoot "project-$count"
        $data = Join-Path $benchRoot "data-$count"
        [IO.Directory]::CreateDirectory($project) | Out-Null
        [IO.Directory]::CreateDirectory($data) | Out-Null
        for ($i=0; $i -lt $count; $i++) {
            [IO.File]::WriteAllText((Join-Path $project "file$i.py"), "def target$i():`n    return $i`n`ndef caller$i():`n    return target$i()`n")
        }
        Measure-Scan $project $data 'cold' $count
        Measure-Scan $project $data 'unchanged' $count
        [IO.File]::AppendAllText((Join-Path $project 'file0.py'), "`ndef added():`n    return target0()`n")
        Measure-Scan $project $data 'single-file-change' $count
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($benchRoot)
    if ($resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('graphxploit-bench-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
