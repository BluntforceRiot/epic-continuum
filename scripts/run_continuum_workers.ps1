[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Root,

    [string] $SourceRoot = (Split-Path -Parent $PSScriptRoot),

    [string] $PythonExe = "python",

    [double] $IntervalSeconds = 5.0,

    [double] $MaintenanceIntervalSeconds = 300.0
)

$ErrorActionPreference = "Stop"

$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
$resolvedSource = (Resolve-Path -LiteralPath $SourceRoot).Path
$sourcePackage = Join-Path $resolvedSource "src"
if (-not (Test-Path -LiteralPath (Join-Path $sourcePackage "continuum") -PathType Container)) {
    throw "Continuum source package was not found under $sourcePackage"
}

if ([System.IO.Path]::IsPathRooted($PythonExe) -and -not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "Python executable was not found: $PythonExe"
}

$env:PYTHONPATH = if ($env:PYTHONPATH) {
    "$sourcePackage;$env:PYTHONPATH"
} else {
    $sourcePackage
}

$logDirectory = Join-Path $resolvedRoot "run\logs"
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$logPath = Join-Path $logDirectory "continuum-workers.log"

"[$(Get-Date -Format o)] starting Epic Continuum workers" | Out-File -LiteralPath $logPath -Append -Encoding utf8
& $PythonExe -m continuum serve `
    --root $resolvedRoot `
    --interval-seconds $IntervalSeconds `
    --maintenance-interval-seconds $MaintenanceIntervalSeconds *>> $logPath
$exitCode = $LASTEXITCODE
"[$(Get-Date -Format o)] Epic Continuum workers exited with code $exitCode" | Out-File -LiteralPath $logPath -Append -Encoding utf8
exit $exitCode
