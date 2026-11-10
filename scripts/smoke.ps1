param([Parameter(Mandatory=$true)][string]$Binary)
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempRoot ('graphxploit-smoke-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$project = Join-Path $testRoot 'source'
[IO.Directory]::CreateDirectory($project) | Out-Null
$server = $null
function Start-Child([string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new($binaryPath)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Environment['GRAPHXPLOIT_DATA_DIR'] = (Join-Path $testRoot 'data')
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $p = [Diagnostics.Process]::new(); $p.StartInfo = $info; [void]$p.Start(); return $p
}
function Invoke-Cli([string[]]$Arguments) {
    $p = Start-Child $Arguments
    $stdout = $p.StandardOutput.ReadToEndAsync(); $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(30000)) { $p.Kill($true); throw 'CLI deadline exceeded' }
    if ($p.ExitCode -ne 0) { throw $stderr.Result }
    $text = $stdout.Result; $p.Dispose(); return $text
}
try {
    [IO.File]::WriteAllText((Join-Path $project 'code.py'), "def target(): pass`ndef caller(): target()`n")
    [IO.File]::WriteAllText((Join-Path $project '.env'), 'FAKE_SECRET=must-not-be-readable')
    [void](Invoke-Cli @('-C',$project,'ix'))
    $found = (Invoke-Cli @('-C',$project,'f','target','--json')) | ConvertFrom-Json
    if ($found.items.Count -ne 1) { throw 'Symbol JSON smoke check failed' }
    $context = (Invoke-Cli @('-C',$project,'ctx','target','--target','target','--format','json')) | ConvertFrom-Json
    if (-not $context.evidence[0].content_hash) { throw 'Context does not contain a source hash' }
    $server = Start-Child @('serve',$project)
    $line = $server.StandardOutput.ReadLineAsync()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $line.IsCompleted -and $timer.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 25 }
    if (-not $line.IsCompleted -or $line.Result -notmatch '(http://127\.0\.0\.1:\d+)') { throw 'Server did not start on loopback' }
    $url = $Matches[1]
    $bootstrap = (Invoke-WebRequest -Uri "$url/bootstrap.js").Content
    if ($bootstrap -notmatch 'GRAPHXPLOIT_TOKEN = "([0-9a-f]+)"') { throw 'Bootstrap token missing' }
    $headers = @{'X-GraphXploit-Token'=$Matches[1]}
    $cap = Invoke-RestMethod -Uri "$url/api/v1/capabilities" -Headers $headers
    $unauth = Invoke-WebRequest -Uri "$url/api/v1/capabilities" -SkipHttpErrorCheck
    if ($unauth.StatusCode -ne 401) { throw 'Missing token was not rejected' }
    $cross = Invoke-WebRequest -Uri "$url/api/v1/capabilities" -Headers @{Origin='https://example.invalid'} -SkipHttpErrorCheck
    if ($cross.StatusCode -ne 403) { throw 'Cross-origin request was not rejected' }
    $overview = Invoke-RestMethod -Uri "$url/api/v1/overview" -Method Post -Headers $headers -ContentType application/json -Body (@{root=$project}|ConvertTo-Json)
    if ($overview.total_files -ne 1) { throw 'Overview scan count incorrect' }
    $graph = Invoke-RestMethod -Uri "$url/api/v1/graph" -Method Post -Headers $headers -ContentType application/json -Body (@{root=$project;target='code.py';depth=2}|ConvertTo-Json)
    if ($graph.nodes.Count -ne 3 -or -not @($graph.edges|Where-Object kind -eq 'CALLS').Count) { throw 'File graph is missing its members or call evidence' }
    $denied = Invoke-WebRequest -Uri "$url/api/v1/source" -Method Post -Headers $headers -ContentType application/json -Body (@{root=$project;path='.env';start_line=1;end_line=10}|ConvertTo-Json) -SkipHttpErrorCheck
    if ($denied.StatusCode -eq 200) { throw 'Secret path was readable' }
    $server.Refresh(); $cpuBefore = $server.TotalProcessorTime.TotalMilliseconds
    Start-Sleep -Seconds 2
    $server.Refresh()
    [pscustomobject]@{edition=$cap.edition;version=$cap.version;cli_json='passed';http_auth_origin='passed';secret_exclusion='passed';file_graph='passed';idle_working_set_bytes=$server.WorkingSet64;idle_cpu_ms_over_two_seconds=($server.TotalProcessorTime.TotalMilliseconds-$cpuBefore)}
} finally {
    if ($server -and -not $server.HasExited) { $server.Kill($true); $server.WaitForExit(); $server.Dispose() }
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if ($resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('graphxploit-smoke-')) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
