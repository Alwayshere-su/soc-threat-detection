param(
    [Parameter(Mandatory=$true)][string]$InputFile,
    [string]$OutFile = "",
    [string]$PythonPath = ""
)
$ErrorActionPreference = 'Stop'
if (-not $PythonPath) {
    $localPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    $parentPython = Join-Path (Split-Path $PSScriptRoot -Parent) '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $localPython) { $PythonPath = $localPython }
    elseif (Test-Path -LiteralPath $parentPython) { $PythonPath = $parentPython }
    else { $PythonPath = 'python' }
}
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'outputs\res.csv' }
& $PythonPath (Join-Path $PSScriptRoot 'reproduce.py') --input $InputFile --out $OutFile
if ($LASTEXITCODE -ne 0) { throw 'Reproduction failed; inspect the output log.' }
