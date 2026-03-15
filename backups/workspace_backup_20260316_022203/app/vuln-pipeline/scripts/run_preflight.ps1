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
New-Item -ItemType Directory -Force -Path $reportDataDir | Out-Null
$readinessJson = Join-Path $reportDataDir "real_input_readiness.json"
$readinessMd = Join-Path $reportDataDir "real_input_readiness.md"

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
    Write-Host "Readiness checker blocked this run. Preflight command was not executed."
    exit $checkerExit
}
if ($CheckOnly) {
    Write-Host "CheckOnly was requested. Preflight command was not executed."
    exit 0
}

$command = @(
    "python", "-m", "vuln_pipeline.cli.main",
    "--run-id", $RunId,
    "--output-base", $OutputBase,
    "--customer-bundle", $CustomerBundle,
    "--branding-file", $BrandingFile,
    "--auto-select-real-inputs",
    "--preflight-only"
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

$inputPreflight = Join-Path $reportDataDir "input_preflight.json"
$selectionJson = Join-Path $reportDataDir "real_input_selection.json"

Write-Host "Preflight artifacts:"
Write-Host "  $inputPreflight"
Write-Host "  $selectionJson"

exit $commandExit
