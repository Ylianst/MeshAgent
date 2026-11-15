param([Parameter(Mandatory=$true)][string]$AgentPath)
$ErrorActionPreference='Stop'
$agent=(Resolve-Path -LiteralPath $AgentPath).Path
$script=Join-Path $PSScriptRoot 'windows-process-environment-tests.js'
$start=New-Object Diagnostics.ProcessStartInfo
$start.FileName=$agent
$start.Arguments='"'+$script+'"'
$start.UseShellExecute=$false
$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true
$start.RedirectStandardError=$true
$process=New-Object Diagnostics.Process
$process.StartInfo=$start
try {
 if(-not $process.Start()){throw 'Test Agent did not start'}
 $stdout=$process.StandardOutput.ReadToEndAsync()
 $stderr=$process.StandardError.ReadToEndAsync()
 if(-not $process.WaitForExit(45000)){$process.Kill();$process.WaitForExit();throw 'Environment tests exceeded 45 seconds'}
 $output=$stdout.Result
 Write-Output $output
 if($process.ExitCode -ne 0 -or $output -match 'FAIL:' -or $output -notmatch 'PASS: 13 native Windows child-environment cases'){throw 'Environment tests failed'}
} finally {$process.Dispose()}
