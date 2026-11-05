# Updates the embedded JS modules with the corresponding files in modules/*.js.
# The file changed (in microscript, ILibDuktape_Polyfills.c or ILibDuktape_EmbeddedModules.c) depends on which is used.
# Done through update-modules.js, run in a built agent binary by default or under node with -node.
param(
    [switch]$Update,
    [string[]]$Add = @(),
    [string[]]$Remove = @(),
    [switch]$Sync,
    [switch]$DryRun,
    [switch]$Export,
    # The optional directory after -Export. A positional parameter is the only way PowerShell lets a flag take a value or not.
    [Parameter(Position = 0)]
    [string]$Dir = '',
    [switch]$List,
    [switch]$Check,
    [string]$BinaryPath = '',
    [switch]$Node,
    [switch]$StripLegacy
)

if ($PSBoundParameters.Count -eq 0) {
    @'
usage: update-modules.ps1 [-Update | -Export [dir] | -List | -Check] [-Add name1,name2] [-Remove name1,name2] [-Sync] [-DryRun] [-StripLegacy] [-BinaryPath path | -Node]

  -Update         update every embedded module whose modules\<name>.js changed. Leaves entries
                  whose source file is gone in place, and does not add anything new
  -Add list       comma-separated module names to update, or add as a new entry when a name is
                  not embedded yet (each needs a matching modules\<name>.js). On its own it
                  touches nothing else; with -Update or -Sync the rest is updated too
  -Remove list    comma-separated module names to drop from the embedded table, whether or not
                  modules\<name>.js still exists. Same rule as -Add for the other entries
  -Sync           in addition to updating, follow modules\ exactly: add any modules\<name>.js
                  with no entry yet, and remove entries whose modules\<name>.js is gone.
  -DryRun         only report what would change.
  -Check          dry run that exits 1 when anything would change, for CI. Combine with -Sync
                  to also fail on a modules\<name>.js that is not embedded yet
  -Export [dir]   save the currently embedded scripts, decompressed, into the directory
                  (default modules_expanded\) and change nothing else
  -List           print the currently embedded module names and sizes, and change nothing else
  -BinaryPath p   the agent to run in. Default is a built MeshConsole from Release\ or Debug\
  -Node           run under a plain 'node' on PATH instead of a MeshConsole binary
  -StripLegacy    moves the embedded modules into ILibDuktape_EmbeddedModules.c: cuts the
                  addCompressedModule() statements out of ILibDuktape_Polyfills.c and adds a
                  call to ILibDuktape_Polyfills_EmbeddedModules(ctx) instead.

'@ | Write-Host
    exit 0
}

Push-Location (Join-Path $PSScriptRoot '..')
try {
    if ($Dir -and -not $Export) {
        Write-Host "Unknown argument: $Dir (a bare value is only accepted as the directory after -Export)"
        exit 1
    }
    $ExportVal = if (-not $Export) { '' } elseif ($Dir) { $Dir } else { 'modules_expanded' }
    # The settings travel as environment variables rather than as JS source, so no value needs escaping: a Windows path
    # pasted into a '...' literal had its backslashes read as escapes (-Export C:\Users\x\Temp\out became "C:UsersxTempout" with a tab in it).
    $env:UPDATE_ROOT = (Get-Location).Path
    $env:UPDATE_UPDATE = [int]$Update.IsPresent
    $env:UPDATE_ADD = ($Add -join ',')
    $env:UPDATE_REMOVE = ($Remove -join ',')
    $env:UPDATE_SYNC = [int]$Sync.IsPresent
    $env:UPDATE_DRYRUN = [int]$DryRun.IsPresent
    $env:UPDATE_CHECK = [int]$Check.IsPresent
    $env:UPDATE_EXPORT = $ExportVal
    $env:UPDATE_LIST = [int]$List.IsPresent
    $env:UPDATE_STRIP_LEGACY = [int]$StripLegacy.IsPresent
    # The chdir is for the agent, which moves to its own directory at startup on Windows.
    $Script = "try { process.chdir(process.env.UPDATE_ROOT); } catch (e) { } try { eval(require('fs').readFileSync('tools/update-modules/update-modules.js').toString()); } catch (e) { console.log(e); process.exit(1); } process.exit(UPDATE_EXIT_CODE);"

    # Under node, pako is what makes the compressed bytes match the agent's. Offer to install it once, only when someone is there to answer.
    function Invoke-Node {
        if (-not (Test-Path -LiteralPath 'tools\update-modules\node_modules\pako' -PathType Container) -and (Get-Command npm -ErrorAction SilentlyContinue) -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
            $answer = Read-Host "pako is not installed under tools\update-modules\, so node's zlib would produce different bytes than the agent. Run 'npm install' there now? [y/N]"
            if ($answer -match '^[Yy]') { Push-Location 'tools\update-modules'; try { & npm install --no-audit --no-fund } finally { Pop-Location } }
        }
        Write-Host "Using node"
        & node -e $Script
        exit $LASTEXITCODE
    }

    if ($Node) {
        if ($BinaryPath) { Write-Host "-Node was passed. Ignoring -BinaryPath $BinaryPath" }
        if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
            Write-Host "-Node was passed but node is not on PATH."
            exit 1
        }
        Invoke-Node
    }

    $Agent = $BinaryPath
    if ($Agent) {
        if (-not (Test-Path -LiteralPath $Agent -PathType Leaf)) {
            Write-Host "-BinaryPath $Agent is not a file"
            exit 1
        }
        # Without a full path, '&' refuses a bare file name, since PowerShell does not look for an executable in the current directory.
        $Agent = (Resolve-Path -LiteralPath $Agent).Path
    }
    else {
        $Agent = @('Release\MeshConsole64.exe', 'Release\MeshConsole.exe', 'Debug\MeshConsole64.exe', 'Debug\MeshConsole.exe') |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $Agent) {
            if (Get-Command node -ErrorAction SilentlyContinue) {
                Write-Host "No agent binary found under Release\ or Debug\. Falling back to node."
                Invoke-Node
            }
            Write-Host "No agent binary found under Release\ or Debug\, and node is not on PATH. Build MeshConsole first, or pass one with -BinaryPath."
            exit 1
        }
    }

    #circumvent 4096 character limit pre-#376 fix
    $ScriptB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Script))

    Write-Host "Using agent: $Agent"
    & $Agent -b64exec $ScriptB64
    exit $LASTEXITCODE
}
finally {
    Pop-Location
    Remove-Item Env:UPDATE_* -ErrorAction SilentlyContinue
}
