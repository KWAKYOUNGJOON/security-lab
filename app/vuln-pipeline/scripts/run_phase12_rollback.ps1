[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [string]$WorkspaceRoot = "",
    [string]$LiveRoot = "",
    [string]$OutputDir = "",
    [string]$ReceiptDir = "",
    [string]$ScanReceiptDir = "",
    [string]$ManualReceiptDir = "",
    [switch]$Apply,
    [switch]$Overwrite
)

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8NoBom
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom

function Resolve-FullPath {
    param([string]$PathValue)
    if (-not $PathValue) {
        return ""
    }
    return [System.IO.Path]::GetFullPath($PathValue)
}

function Ensure-Directory {
    param([string]$PathValue)
    if ($PathValue -and -not (Test-Path $PathValue)) {
        New-Item -ItemType Directory -Force -Path $PathValue | Out-Null
    }
}

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoWorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$resolvedRunRoot = Resolve-FullPath $RunRoot

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = $repoWorkspaceRoot
}
if (-not $LiveRoot) {
    $LiveRoot = Join-Path $WorkspaceRoot "data\inputs\real"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $resolvedRunRoot "report_data"
}

$WorkspaceRoot = Resolve-FullPath $WorkspaceRoot
$LiveRoot = Resolve-FullPath $LiveRoot
$OutputDir = Resolve-FullPath $OutputDir
Ensure-Directory -PathValue $OutputDir

$args = @(
    "-m", "vuln_pipeline.cli.phase12_rollback",
    "--run-root", $resolvedRunRoot,
    "--workspace-root", $WorkspaceRoot,
    "--live-root", $LiveRoot,
    "--output-dir", $OutputDir
)
if ($ReceiptDir) {
    $args += "--receipt-dir"
    $args += (Resolve-FullPath $ReceiptDir)
}
if ($ScanReceiptDir) {
    $args += "--scan-receipt-dir"
    $args += (Resolve-FullPath $ScanReceiptDir)
}
if ($ManualReceiptDir) {
    $args += "--manual-receipt-dir"
    $args += (Resolve-FullPath $ManualReceiptDir)
}
if ($Apply) {
    $args += "--apply"
    if ($Overwrite) {
        $args += "--overwrite"
    }
}
else {
    $args += "--plan-only"
}

Push-Location $appRoot
try {
    & python $args
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

$planJson = Join-Path $OutputDir "phase12_rollback_plan.json"
$planMd = Join-Path $OutputDir "phase12_rollback_plan.md"
$receiptJson = Join-Path $OutputDir "phase12_rollback_receipt.json"
$receiptMd = Join-Path $OutputDir "phase12_rollback_receipt.md"

Write-Host "Rollback artifacts:"
Write-Host "  $planJson"
Write-Host "  $planMd"
Write-Host "  $receiptJson"
Write-Host "  $receiptMd"

if ($exitCode -ne 0) {
    Write-Host "Rollback flow was blocked or failed. Review the rollback plan/receipt artifacts above."
}

exit $exitCode
