@echo off
setlocal

set "OUTPUTS_ROOT=%~1"
if "%OUTPUTS_ROOT%"=="" set "OUTPUTS_ROOT=%~dp0..\..\..\outputs"

for %%I in ("%OUTPUTS_ROOT%") do set "OUTPUTS_ROOT=%%~fI"

set "OUTPUTS_ROOT=%OUTPUTS_ROOT%"
for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command ^
    "$root = [System.IO.Path]::GetFullPath($env:OUTPUTS_ROOT);" ^
    "New-Item -ItemType Directory -Path $root -Force | Out-Null;" ^
    "$date = Get-Date -Format 'yyyy-MM-dd';" ^
    "$pattern = 'run_' + $date + '_*';" ^
    "$existing = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $pattern } | Select-Object -ExpandProperty Name;" ^
    "$max = 0;" ^
    "foreach ($name in $existing) { if ($name -match '^run_\d{4}-\d{2}-\d{2}_(\d{3})$') { $value = [int]$matches[1]; if ($value -gt $max) { $max = $value } } }" ^
    "$next = '{0:D3}' -f ($max + 1);" ^
    "$target = Join-Path $root ('run_' + $date + '_' + $next);" ^
    "New-Item -ItemType Directory -Path $target -Force | Out-Null;" ^
    "New-Item -ItemType Directory -Path (Join-Path $target 'screenshots') -Force | Out-Null;" ^
    "if (-not (Test-Path (Join-Path $target 'notes.txt'))) { New-Item -ItemType File -Path (Join-Path $target 'notes.txt') -Force | Out-Null }" ^
    "Write-Output $target"` ) do set "RUN_DIR=%%I"

if "%RUN_DIR%"=="" (
    echo Failed to create run folder.
    exit /b 1
)

echo %RUN_DIR%
exit /b 0
