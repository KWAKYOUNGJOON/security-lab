@echo off
setlocal

if "%~2"=="" goto usage

set "RUN_DIR=%~1"
set "TARGET=%~2"
set "AUTHOR=%~3"
set "OUTPUT_DIR=%~4"

if "%OUTPUT_DIR%"=="" (
    if "%AUTHOR%"=="" (
        python "%~dp0..\pipeline.py" --run-dir "%RUN_DIR%" --target "%TARGET%" --include-banner --docx
    ) else (
        python "%~dp0..\pipeline.py" --run-dir "%RUN_DIR%" --target "%TARGET%" --author "%AUTHOR%" --include-banner --docx
    )
) else (
    if "%AUTHOR%"=="" (
        python "%~dp0..\pipeline.py" --run-dir "%RUN_DIR%" --target "%TARGET%" --include-banner --docx --output-dir "%OUTPUT_DIR%"
    ) else (
        python "%~dp0..\pipeline.py" --run-dir "%RUN_DIR%" --target "%TARGET%" --author "%AUTHOR%" --include-banner --docx --output-dir "%OUTPUT_DIR%"
    )
)
exit /b %errorlevel%

:usage
echo Usage: %~nx0 RUN_DIR TARGET [AUTHOR] [OUTPUT_DIR]
echo Example 1: %~nx0 "D:\취약점 진단\outputs\run_2026-03-15_001" "https://target.example" "analyst"
echo Example 2: %~nx0 "D:\취약점 진단\outputs\run_2026-03-15_001" "https://target.example" "analyst" "D:\취약점 진단\보고서\artifacts\run_2026-03-15_001"
exit /b 1
