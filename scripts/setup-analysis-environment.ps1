# Explicit opt-in setup. Never invoked automatically by an analysis task.
param(
    [switch]$Apply,
    [string]$Directory = (Join-Path $env:LOCALAPPDATA 'ClineEnhanced\analysis-python'),
    [string]$Python
)
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathRooted($Directory)) { throw 'Absolute environment directory required' }
$requirements = Join-Path $PSScriptRoot '../sdk/packages/core/scripts/requirements-advanced-windows.txt'
$interpreter = Join-Path $Directory 'Scripts/python.exe'
Write-Host "Plan: Python 3.13 virtual environment at $Directory"
Write-Host "Pinned packages: $requirements"
Write-Host 'Miasm may require the supported x64 Visual C++ build environment.'
Write-Host 'No IDA, Hex-Rays license, Keystone, Android device, or isolated worker is installed.'
if (-not $Apply) { Write-Host 'No changes. Pass -Apply to install.'; exit 0 }
if (Test-Path $Directory) {
    if (-not (Test-Path (Join-Path $Directory 'pyvenv.cfg'))) { throw 'Refusing to modify a non-venv directory' }
} elseif ($Python) {
    if (-not [IO.Path]::IsPathRooted($Python)) { throw 'Absolute trusted Python path required' }
    & $Python -m venv $Directory
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed' }
} else {
    & py -3.13 -m venv $Directory
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 required; supply an absolute trusted -Python path if needed' }
}
& $interpreter -m pip install --disable-pip-version-check -r $requirements
if ($LASTEXITCODE -ne 0) { throw 'Pinned engine installation failed; CLINE_RE_PYTHON was not changed' }
& $interpreter -I -c "import sys,lief,capstone,androguard,z3,miasm,cryptography; print(sys.executable); print(sys.version)"
if ($LASTEXITCODE -ne 0) { throw 'Isolated engine imports failed; CLINE_RE_PYTHON was not changed' }
[Environment]::SetEnvironmentVariable('CLINE_RE_PYTHON', $interpreter, 'User')
$env:CLINE_RE_PYTHON = $interpreter
Write-Host "Configured $interpreter. Fully stop Cline and its backend, then launch from this environment."
Write-Host 'Run Settings -> Analysis environment -> Check analysis readiness. Imports are not fixture proof.'