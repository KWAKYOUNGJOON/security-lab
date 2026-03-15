[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [string]$OutputBase,
    [string]$OverrideFile,
    [string]$SuppressionFile,
    [string]$ReviewResolutionFile,
    [string]$CustomerBundle,
    [string]$BrandingFile,
    [string]$ReadinessPolicy,
    [string]$CompareToRun = "",
    [switch]$RequirePptx,
    [switch]$StageRealInputs,
    [switch]$CheckOnly
)

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8NoBom
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if (-not $PSBoundParameters.ContainsKey("OutputBase")) {
    $OutputBase = Join-Path $workspaceRoot "outputs\runs"
}
if (-not $PSBoundParameters.ContainsKey("CustomerBundle")) {
    $CustomerBundle = Join-Path $appRoot "configs\customer_bundles\default_customer_release.yaml"
}
if (-not $PSBoundParameters.ContainsKey("BrandingFile")) {
    $BrandingFile = Join-Path $appRoot "configs\branding\customer_branding.yaml"
}

$runRoot = Join-Path $OutputBase $RunId
$reportDataDir = Join-Path $runRoot "report_data"
$deliveryDir = Join-Path $runRoot "delivery"
$deliverablesDir = Join-Path $runRoot "deliverables"
$realManualDir = Join-Path $workspaceRoot "data\inputs\real\manual"
New-Item -ItemType Directory -Force -Path $reportDataDir | Out-Null
$readinessJson = Join-Path $reportDataDir "real_input_readiness.json"
$readinessMd = Join-Path $reportDataDir "real_input_readiness.md"

function Invoke-PostRunTriage {
    param(
        [string]$RunRootPath,
        [string]$ReportDataPath,
        [string]$ManualDirPath
    )

    $triageJson = Join-Path $ReportDataPath "post_run_triage.json"
    $triageMd = Join-Path $ReportDataPath "post_run_triage.md"
    $triageCsv = Join-Path $ReportDataPath "post_run_triage_worklist.csv"
    $manualValidationJson = Join-Path $ReportDataPath "manual_validation.json"
    $manualValidationMd = Join-Path $ReportDataPath "manual_validation.md"

    $command = @(
        "python", "-m", "vuln_pipeline.cli.post_run_triage",
        "--run-root", $RunRootPath,
        "--manual-dir", $ManualDirPath,
        "--output-dir", $ReportDataPath,
        "--json-out", $triageJson,
        "--md-out", $triageMd,
        "--csv-out", $triageCsv
    )

    Push-Location $appRoot
    try {
        & $command[0] $command[1..($command.Length - 1)]
        $triageExit = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    $reviewQueueJsonl = Join-Path $ReportDataPath "review_queue.jsonl"
    $reviewQueueCsv = Join-Path $ReportDataPath "review_queue.csv"
    Write-Host "Triage artifacts:"
    Write-Host "  $triageJson"
    Write-Host "  $triageMd"
    Write-Host "  $triageCsv"
    Write-Host "  $manualValidationJson"
    Write-Host "  $manualValidationMd"
    if (Test-Path $reviewQueueJsonl) {
        Write-Host "  $reviewQueueJsonl"
    }
    elseif (Test-Path $reviewQueueCsv) {
        Write-Host "  $reviewQueueCsv"
    }
    else {
        Write-Host "  $(Join-Path $ReportDataPath 'review_queue.*')"
    }
    return $triageExit
}

$checkerArgs = @{
    WorkspaceRoot = $workspaceRoot
    CustomerBundle = $CustomerBundle
    BrandingFile = $BrandingFile
    JsonOut = $readinessJson
    MarkdownOut = $readinessMd
}
if ($PSBoundParameters.ContainsKey("ReadinessPolicy")) { $checkerArgs["ReadinessPolicy"] = $ReadinessPolicy }
if ($PSBoundParameters.ContainsKey("OverrideFile")) { $checkerArgs["OverrideFile"] = $OverrideFile }
if ($PSBoundParameters.ContainsKey("SuppressionFile")) { $checkerArgs["SuppressionFile"] = $SuppressionFile }
if ($PSBoundParameters.ContainsKey("ReviewResolutionFile")) { $checkerArgs["ReviewResolutionFile"] = $ReviewResolutionFile }

& (Join-Path $PSScriptRoot "check_real_input_readiness.ps1") @checkerArgs
$checkerExit = $LASTEXITCODE

Write-Host "Readiness artifacts:"
Write-Host "  $readinessJson"
Write-Host "  $readinessMd"

if ($checkerExit -ne 0) {
    $triageExit = Invoke-PostRunTriage -RunRootPath $runRoot -ReportDataPath $reportDataDir -ManualDirPath $realManualDir
    Write-Host "Readiness checker blocked this run. Rehearsal command was not executed."
    exit $checkerExit
}
if ($CheckOnly) {
    Write-Host "CheckOnly was requested. Rehearsal command was not executed."
    exit 0
}

$command = @(
    "python", "-m", "vuln_pipeline.cli.main",
    "--run-id", $RunId,
    "--output-base", $OutputBase,
    "--customer-bundle", $CustomerBundle,
    "--branding-file", $BrandingFile,
    "--auto-select-real-inputs",
    "--package-output"
)
if ($PSBoundParameters.ContainsKey("OverrideFile")) { $command += @("--override-file", $OverrideFile) }
if ($PSBoundParameters.ContainsKey("SuppressionFile")) { $command += @("--suppression-file", $SuppressionFile) }
if ($PSBoundParameters.ContainsKey("ReviewResolutionFile")) { $command += @("--review-resolution-file", $ReviewResolutionFile) }
if ($PSBoundParameters.ContainsKey("ReadinessPolicy")) { $command += @("--readiness-policy", $ReadinessPolicy) }
if ($CompareToRun) { $command += @("--compare-to-run", $CompareToRun) }
if ($RequirePptx) { $command += "--require-pptx" }
if ($StageRealInputs) { $command += "--stage-real-inputs" }

Push-Location $appRoot
try {
    & $command[0] $command[1..($command.Length - 1)]
    $commandExit = $LASTEXITCODE
}
finally {
    Pop-Location
}

$blockedMd = Join-Path $deliverablesDir "real_rehearsal_blocked.md"
$releaseReadiness = Join-Path $reportDataDir "release_readiness.json"
$submissionGate = Join-Path $reportDataDir "submission_gate.json"
$finalManifest = Join-Path $deliveryDir "final_delivery_manifest.json"
$reviewClosure = Join-Path $reportDataDir "review_closure_status.json"
$customerZip = Get-ChildItem -Path $deliveryDir -Filter "customer_submission_*.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$internalZip = Get-ChildItem -Path $deliveryDir -Filter "internal_archive_*.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Write-Host "Rehearsal artifacts:"
Write-Host "  $blockedMd"
Write-Host "  $releaseReadiness"
Write-Host "  $submissionGate"
Write-Host "  $finalManifest"
Write-Host "  $reviewClosure"
if ($customerZip) {
    Write-Host "  $($customerZip.FullName)"
}
else {
    Write-Host "  $(Join-Path $deliveryDir 'customer_submission_*.zip')"
}
if ($internalZip) {
    Write-Host "  $($internalZip.FullName)"
}
else {
    Write-Host "  $(Join-Path $deliveryDir 'internal_archive_*.zip')"
}

$triageExit = Invoke-PostRunTriage -RunRootPath $runRoot -ReportDataPath $reportDataDir -ManualDirPath $realManualDir
if ($commandExit -ne 0) {
    exit $commandExit
}
exit $triageExit
