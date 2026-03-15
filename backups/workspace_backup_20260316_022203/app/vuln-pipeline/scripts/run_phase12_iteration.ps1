[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [string]$WorkingDir = "",
    [string]$WorkspaceRoot = "",
    [string]$OutputBase,
    [string]$LiveManualDir,
    [string]$LiveRoot,
    [string]$IncomingScanRoot = "",
    [string]$IncomingBurp = "",
    [string]$IncomingNuclei = "",
    [string]$IncomingHttpx = "",
    [string]$PreviousRunRoot = "",
    [string]$PreviousRunId = "",
    [string]$SeedManualDraftsFromRunRoot = "",
    [switch]$SeedManualDraftsFromTemplates,
    [switch]$InitWorkspace,
    [switch]$StopAfterBootstrap,
    [string]$ScanPromotionOutputDir = "",
    [string]$ScanArchiveDir = "",
    [string]$ScanReceiptOut = "",
    [string]$PromotionOutputDir = "",
    [string]$PromotionBackupDir = "",
    [string]$PromotionReceiptOut = "",
    [string]$CustomerBundle,
    [string]$BrandingFile,
    [string]$ReadinessPolicy,
    [string]$TargetNameBurp = "",
    [string]$TargetNameNuclei = "",
    [string]$TargetNameHttpx = "",
    [string]$IntentFile = "",
    [switch]$GenerateSignoffReview,
    [switch]$StopAfterSignoffReview,
    [switch]$RequireIntentForApply,
    [switch]$ApplyScanPromotion,
    [switch]$ApplyPromotion,
    [switch]$Overwrite,
    [switch]$AllowAutoPick,
    [switch]$StageRealInputs,
    [switch]$RequirePptx
)

function Resolve-FullPath {
    param([string]$PathValue)
    if (-not $PathValue) {
        return ""
    }
    return [System.IO.Path]::GetFullPath($PathValue)
}

function Ensure-Directory {
    param([string]$PathValue)
    if (-not (Test-Path $PathValue)) {
        New-Item -ItemType Directory -Force -Path $PathValue | Out-Null
    }
}

function Write-JsonArtifact {
    param(
        [string]$PathValue,
        [hashtable]$Payload
    )
    Ensure-Directory -PathValue (Split-Path -Parent $PathValue)
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($PathValue, ($Payload | ConvertTo-Json -Depth 20), $encoding)
}

function Write-TextArtifact {
    param(
        [string]$PathValue,
        [string]$Content
    )
    Ensure-Directory -PathValue (Split-Path -Parent $PathValue)
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($PathValue, $Content, $encoding)
}

function Invoke-AppPython {
    param([string[]]$Arguments)
    Push-Location $appRoot
    try {
        & python $Arguments | Out-Null
        return $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}

function Get-WorkspaceRootForInit {
    if ($WorkspaceRoot) {
        return (Resolve-FullPath $WorkspaceRoot)
    }
    if ($WorkingDir) {
        $candidate = Resolve-FullPath $WorkingDir
        if ([System.IO.Path]::GetFileName($candidate) -eq "manual-drafts") {
            return [System.IO.Path]::GetDirectoryName($candidate)
        }
    }
    if ($IncomingScanRoot) {
        $candidate = Resolve-FullPath $IncomingScanRoot
        if ([System.IO.Path]::GetFileName($candidate) -eq "incoming") {
            return [System.IO.Path]::GetDirectoryName($candidate)
        }
    }
    return (Join-Path $repoWorkspaceRoot "notes\phase12-operator-workspace")
}

function Invoke-WorkspaceBootstrap {
    param(
        [string]$ResolvedWorkspaceRoot,
        [string]$ResolvedPreviousRunRoot
    )

    $bootstrapArgs = @(
        "-m", "vuln_pipeline.cli.phase12_operator_workspace",
        "bootstrap",
        "--workspace-root", $ResolvedWorkspaceRoot,
        "--run-id", $RunId,
        "--live-root", $LiveRoot,
        "--live-manual-dir", $LiveManualDir
    )
    if ($ResolvedPreviousRunRoot) {
        $bootstrapArgs += "--previous-run-root"
        $bootstrapArgs += $ResolvedPreviousRunRoot
    }
    if ($SeedManualDraftsFromRunRoot) {
        $bootstrapArgs += "--seed-from-run-root"
        $bootstrapArgs += (Resolve-FullPath $SeedManualDraftsFromRunRoot)
    }
    elseif ($SeedManualDraftsFromTemplates) {
        $bootstrapArgs += "--seed-from-templates"
    }
    if ($Overwrite) {
        $bootstrapArgs += "--overwrite"
    }
    return (Invoke-AppPython -Arguments $bootstrapArgs)
}

function Write-OperatorCase {
    param(
        [string]$CasePhase,
        [string]$ResolvedWorkspaceRoot,
        [string]$ResolvedPreviousRunRoot
    )

    $caseArgs = @(
        "-m", "vuln_pipeline.cli.phase12_operator_workspace",
        "operator-case",
        "--case-phase", $CasePhase,
        "--run-id", $RunId,
        "--run-root", $runRoot,
        "--working-dir", $WorkingDir,
        "--incoming-root", $IncomingScanRoot,
        "--live-root", $LiveRoot,
        "--live-manual-dir", $LiveManualDir,
        "--wrapper-script", (Join-Path $PSScriptRoot "run_phase12_iteration.ps1"),
        "--app-root", $appRoot,
        "--json-out", $operatorCaseJson,
        "--markdown-out", $operatorCaseMd
    )
    if ($ResolvedWorkspaceRoot) {
        $caseArgs += "--workspace-root"
        $caseArgs += $ResolvedWorkspaceRoot
    }
    if ($ResolvedPreviousRunRoot) {
        $caseArgs += "--previous-run-root"
        $caseArgs += $ResolvedPreviousRunRoot
    }
    if ($CustomerBundle) {
        $caseArgs += "--customer-bundle"
        $caseArgs += $CustomerBundle
    }
    if ($BrandingFile) {
        $caseArgs += "--branding-file"
        $caseArgs += $BrandingFile
    }
    if ($ReadinessPolicy) {
        $caseArgs += "--readiness-policy"
        $caseArgs += $ReadinessPolicy
    }
    if ($ApplyScanPromotion) {
        $caseArgs += "--apply-scan-promotion"
    }
    if ($ApplyPromotion) {
        $caseArgs += "--apply-promotion"
    }
    return (Invoke-AppPython -Arguments $caseArgs)
}

function Write-ManualPromotionStub {
    param([string]$Reason)

    $plan = @{
        status = "blocked"
        mode = "plan"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        working_dir = $WorkingDir
        live_manual_dir = $LiveManualDir
        output_dir = $PromotionOutputDir
        blockers = @($Reason)
        warnings = @(
            "manual promotion was skipped by the wrapper because the non-live working drafts are not ready",
            "use workspace bootstrap or manual_bootstrap before rerunning manual_promotion"
        )
        operator_guidance = @(
            "bootstrap or seed the non-live manual-drafts directory first",
            "review draft_candidates manually before any live apply step"
        )
    }
    Write-JsonArtifact -PathValue $promotionPlanJson -Payload $plan
    $markdown = @(
        '# Manual Promotion Plan',
        '',
        '- status: `blocked`',
        "- reason: $Reason",
        "- working_dir: ``$WorkingDir``",
        "- live_manual_dir: ``$LiveManualDir``",
        '',
        '## Next Step',
        '- initialize the non-live workspace or seed manual working drafts before rerunning manual_promotion'
    ) -join "`n"
    Write-TextArtifact -PathValue $promotionPlanMd -Content ($markdown + "`n")
}

function Invoke-SignoffReview {
    param(
        [string]$ResolvedWorkspaceRoot,
        [string]$ResolvedPreviousRunRoot
    )

    $args = @(
        "-m", "vuln_pipeline.cli.phase12_apply_signoff",
        "review",
        "--run-id", $RunId,
        "--output-dir", $reportDataDir,
        "--scan-plan-dir", $ScanPromotionOutputDir,
        "--manual-plan-dir", $PromotionOutputDir,
        "--operator-case", $operatorCaseJson,
        "--review-json-out", $signoffReviewJson,
        "--review-md-out", $signoffReviewMd,
        "--intent-template-out", $signoffIntentTemplate
    )
    if ($ResolvedWorkspaceRoot) {
        $args += "--workspace-root"
        $args += $ResolvedWorkspaceRoot
    }
    if ($ResolvedPreviousRunRoot) {
        $args += "--previous-run-root"
        $args += $ResolvedPreviousRunRoot
    }
    return (Invoke-AppPython -Arguments $args)
}

function Invoke-IntentValidation {
    param(
        [string]$ResolvedIntentFile
    )

    $args = @(
        "-m", "vuln_pipeline.cli.phase12_apply_signoff",
        "validate-intent",
        "--intent-file", $ResolvedIntentFile,
        "--review-json", $signoffReviewJson,
        "--validation-json-out", $intentValidationJson,
        "--validation-md-out", $intentValidationMd
    )
    if ($ApplyScanPromotion) {
        $args += "--apply-scan-requested"
    }
    if ($ApplyPromotion) {
        $args += "--apply-manual-requested"
    }
    return (Invoke-AppPython -Arguments $args)
}

function Invoke-EvidencePack {
    param(
        [string]$ResolvedWorkspaceRoot,
        [string]$ResolvedPreviousRunRoot,
        [string]$ResolvedIntentFile
    )

    $args = @(
        "-m", "vuln_pipeline.cli.phase12_evidence_pack",
        "--run-root", $runRoot,
        "--output-dir", $reportDataDir,
        "--intent-validation-json", $intentValidationJson
    )
    if ($ResolvedWorkspaceRoot) {
        $args += "--workspace-root"
        $args += $ResolvedWorkspaceRoot
    }
    if ($ResolvedPreviousRunRoot) {
        $args += "--previous-run-root"
        $args += $ResolvedPreviousRunRoot
    }
    if ($ResolvedIntentFile) {
        $args += "--intent-file"
        $args += $ResolvedIntentFile
    }
    if ($ApplyScanPromotion) {
        $args += "--apply-scan-requested"
    }
    if ($ApplyPromotion) {
        $args += "--apply-manual-requested"
    }
    return (Invoke-AppPython -Arguments $args)
}

function Test-ManualDraftsReady {
    if (-not (Test-Path $WorkingDir)) {
        return $false
    }
    foreach ($name in @("override_working.yaml", "suppression_working.yaml", "review_resolution_working.yaml")) {
        if (-not (Test-Path (Join-Path $WorkingDir $name))) {
            return $false
        }
    }
    return $true
}

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoWorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if (-not $PSBoundParameters.ContainsKey("OutputBase")) {
    $OutputBase = Join-Path $repoWorkspaceRoot "outputs\runs"
}
if (-not $PSBoundParameters.ContainsKey("LiveManualDir")) {
    $LiveManualDir = Join-Path $repoWorkspaceRoot "data\inputs\real\manual"
}
if (-not $PSBoundParameters.ContainsKey("LiveRoot")) {
    $LiveRoot = Join-Path $repoWorkspaceRoot "data\inputs\real"
}

$resolvedWorkspaceRoot = ""
if ($WorkspaceRoot -or $InitWorkspace) {
    $resolvedWorkspaceRoot = Get-WorkspaceRootForInit
    $WorkspaceRoot = $resolvedWorkspaceRoot
}
if ($resolvedWorkspaceRoot -and -not $WorkingDir) {
    $WorkingDir = Join-Path $resolvedWorkspaceRoot "manual-drafts"
}
if ($resolvedWorkspaceRoot -and -not $IncomingScanRoot) {
    $IncomingScanRoot = Join-Path $resolvedWorkspaceRoot "incoming"
}
if (-not $WorkingDir) {
    $WorkingDir = Join-Path $repoWorkspaceRoot "notes\phase12-manual-drafts"
}
if (-not $IncomingScanRoot) {
    $IncomingScanRoot = Join-Path $repoWorkspaceRoot "notes\phase12-operator-workspace\incoming"
}

$WorkingDir = Resolve-FullPath $WorkingDir
$IncomingScanRoot = Resolve-FullPath $IncomingScanRoot
$LiveManualDir = Resolve-FullPath $LiveManualDir
$LiveRoot = Resolve-FullPath $LiveRoot
$OutputBase = Resolve-FullPath $OutputBase

$runRoot = Join-Path $OutputBase $RunId
$reportDataDir = Join-Path $runRoot "report_data"
Ensure-Directory -PathValue $reportDataDir

$operatorCaseJson = Join-Path $reportDataDir "phase12_operator_case.json"
$operatorCaseMd = Join-Path $reportDataDir "phase12_operator_case.md"
$signoffReviewJson = Join-Path $reportDataDir "phase12_signoff_review.json"
$signoffReviewMd = Join-Path $reportDataDir "phase12_signoff_review.md"
$signoffIntentTemplate = Join-Path $reportDataDir "phase12_apply_intent.template.json"
$intentValidationJson = Join-Path $reportDataDir "phase12_apply_intent_validation.json"
$intentValidationMd = Join-Path $reportDataDir "phase12_apply_intent_validation.md"
$evidencePackJson = Join-Path $reportDataDir "phase12_evidence_pack.json"
$evidencePackMd = Join-Path $reportDataDir "phase12_evidence_pack.md"

if (-not $ScanPromotionOutputDir) {
    $ScanPromotionOutputDir = Join-Path $reportDataDir "scan_promotion"
}
if (-not $ScanArchiveDir) {
    $ScanArchiveDir = Join-Path $ScanPromotionOutputDir "archive"
}
if (-not $ScanReceiptOut) {
    $ScanReceiptOut = Join-Path $ScanPromotionOutputDir "scan_input_promotion_receipt.json"
}
if (-not $PromotionOutputDir) {
    $PromotionOutputDir = Join-Path $reportDataDir "manual_promotion"
}
if (-not $PromotionBackupDir) {
    $PromotionBackupDir = Join-Path $PromotionOutputDir "backups"
}
if (-not $PromotionReceiptOut) {
    $PromotionReceiptOut = Join-Path $PromotionOutputDir "manual_promotion_receipt.json"
}
Ensure-Directory -PathValue $ScanPromotionOutputDir
Ensure-Directory -PathValue $PromotionOutputDir

$scanPromotionPlanJson = Join-Path $ScanPromotionOutputDir "scan_input_promotion_plan.json"
$scanPromotionPlanMd = Join-Path $ScanPromotionOutputDir "scan_input_promotion_plan.md"
$liveScanInventoryJson = Join-Path $ScanPromotionOutputDir "live_scan_inventory.json"
$liveScanInventoryMd = Join-Path $ScanPromotionOutputDir "live_scan_inventory.md"
$scanPromotionReceiptMd = Join-Path $ScanPromotionOutputDir "scan_input_promotion_receipt.md"

$promotionPlanJson = Join-Path $PromotionOutputDir "manual_promotion_plan.json"
$promotionPlanMd = Join-Path $PromotionOutputDir "manual_promotion_plan.md"
$promotionReceiptMd = Join-Path $PromotionOutputDir "manual_promotion_receipt.md"

$resolvedPreviousRunRoot = ""
if ($PreviousRunRoot) {
    $resolvedPreviousRunRoot = Resolve-FullPath $PreviousRunRoot
}
elseif ($PreviousRunId) {
    $candidatePreviousRoot = Join-Path $OutputBase $PreviousRunId
    if (Test-Path $candidatePreviousRoot) {
        $resolvedPreviousRunRoot = (Resolve-Path $candidatePreviousRoot).Path
    }
}

$bootstrapManifestJson = ""
$bootstrapManifestMd = ""
if ($resolvedWorkspaceRoot) {
    $bootstrapManifestJson = Join-Path $resolvedWorkspaceRoot "phase12_workspace_manifest.json"
    $bootstrapManifestMd = Join-Path $resolvedWorkspaceRoot "phase12_workspace_manifest.md"
}

$resolvedIntentFile = ""
if ($IntentFile) {
    $resolvedIntentFile = Resolve-FullPath $IntentFile
}
$intentRequired = $RequireIntentForApply -or $ApplyScanPromotion -or $ApplyPromotion
$scanApplyAllowed = $ApplyScanPromotion
$manualApplyAllowed = $ApplyPromotion
$intentGateReasons = @()

$null = Write-OperatorCase -CasePhase "pre-run" -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot

if ($InitWorkspace) {
    $bootstrapExit = Invoke-WorkspaceBootstrap -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
    Write-Host "Workspace bootstrap artifacts:"
    Write-Host "  $bootstrapManifestJson"
    Write-Host "  $bootstrapManifestMd"
    if ($bootstrapExit -ne 0) {
        $null = Write-OperatorCase -CasePhase "bootstrap-failed" -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
        exit $bootstrapExit
    }
    if (-not $WorkingDir) {
        $WorkingDir = Join-Path $resolvedWorkspaceRoot "manual-drafts"
    }
    if (-not $IncomingScanRoot) {
        $IncomingScanRoot = Join-Path $resolvedWorkspaceRoot "incoming"
    }
    $WorkingDir = Resolve-FullPath $WorkingDir
    $IncomingScanRoot = Resolve-FullPath $IncomingScanRoot
    $null = Write-OperatorCase -CasePhase "post-bootstrap" -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
    if ($StopAfterBootstrap) {
        Write-Host "Bootstrap-only flow completed."
        Write-Host "Operator case artifacts:"
        Write-Host "  $operatorCaseJson"
        Write-Host "  $operatorCaseMd"
        exit 0
    }
}

$scanPromotionArgs = @(
    "-m", "vuln_pipeline.cli.scan_input_promotion",
    "--live-root", $LiveRoot,
    "--output-dir", $ScanPromotionOutputDir,
    "--plan-only"
)
if ($IncomingScanRoot) {
    $scanPromotionArgs += "--incoming-root"
    $scanPromotionArgs += $IncomingScanRoot
}
if ($IncomingBurp) {
    $scanPromotionArgs += "--incoming-burp"
    $scanPromotionArgs += (Resolve-FullPath $IncomingBurp)
}
if ($IncomingNuclei) {
    $scanPromotionArgs += "--incoming-nuclei"
    $scanPromotionArgs += (Resolve-FullPath $IncomingNuclei)
}
if ($IncomingHttpx) {
    $scanPromotionArgs += "--incoming-httpx"
    $scanPromotionArgs += (Resolve-FullPath $IncomingHttpx)
}
if ($TargetNameBurp) {
    $scanPromotionArgs += "--target-name-burp"
    $scanPromotionArgs += $TargetNameBurp
}
if ($TargetNameNuclei) {
    $scanPromotionArgs += "--target-name-nuclei"
    $scanPromotionArgs += $TargetNameNuclei
}
if ($TargetNameHttpx) {
    $scanPromotionArgs += "--target-name-httpx"
    $scanPromotionArgs += $TargetNameHttpx
}
if ($AllowAutoPick) {
    $scanPromotionArgs += "--allow-auto-pick"
}
$scanPromotionExit = Invoke-AppPython -Arguments $scanPromotionArgs
Write-Host "Scan promotion artifacts:"
Write-Host "  $scanPromotionPlanJson"
Write-Host "  $scanPromotionPlanMd"
Write-Host "  $liveScanInventoryJson"
Write-Host "  $liveScanInventoryMd"

$manualPromotionExit = 0
if (Test-ManualDraftsReady) {
    $promotionArgs = @(
        "-m", "vuln_pipeline.cli.manual_promotion",
        "--working-dir", $WorkingDir,
        "--live-manual-dir", $LiveManualDir,
        "--output-dir", $PromotionOutputDir,
        "--plan-only"
    )
    $manualPromotionExit = Invoke-AppPython -Arguments $promotionArgs
}
else {
    $manualReason = if (-not (Test-Path $WorkingDir)) {
        "Working directory does not exist: $WorkingDir"
    }
    else {
        "Working directory is missing one or more required files: override_working.yaml, suppression_working.yaml, review_resolution_working.yaml"
    }
    Write-Host "Manual promotion was not executed."
    Write-Host "  $manualReason"
    Write-ManualPromotionStub -Reason $manualReason
    if ($manualApplyAllowed) {
        $manualPromotionExit = 1
    }
}

Write-Host "Promotion artifacts:"
Write-Host "  $promotionPlanJson"
Write-Host "  $promotionPlanMd"

$shouldGenerateSignoff = $GenerateSignoffReview -or $StopAfterSignoffReview -or $intentRequired
if ($shouldGenerateSignoff) {
    $signoffExit = Invoke-SignoffReview -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
    Write-Host "Signoff artifacts:"
    Write-Host "  $signoffReviewJson"
    Write-Host "  $signoffReviewMd"
    Write-Host "  $signoffIntentTemplate"
    if ($signoffExit -ne 0) {
        $intentGateReasons += "signoff review generation failed"
    }
}

if ($StopAfterSignoffReview) {
    $null = Write-OperatorCase -CasePhase "signoff-review" -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
    $null = Invoke-EvidencePack -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot -ResolvedIntentFile $resolvedIntentFile
    Write-Host "Signoff-review-only flow completed."
    Write-Host "Evidence artifacts:"
    Write-Host "  $evidencePackJson"
    Write-Host "  $evidencePackMd"
    exit 0
}

if ($intentRequired) {
    if (-not $resolvedIntentFile) {
        $intentGateReasons += "apply was requested but no -IntentFile was provided"
    }
    elseif (-not (Test-Path $resolvedIntentFile)) {
        $intentGateReasons += "intent file does not exist: $resolvedIntentFile"
    }
    else {
        $intentValidationExit = Invoke-IntentValidation -ResolvedIntentFile $resolvedIntentFile
        Write-Host "Intent validation artifacts:"
        Write-Host "  $intentValidationJson"
        Write-Host "  $intentValidationMd"
        if ($intentValidationExit -ne 0) {
            $intentGateReasons += "intent validation failed or intent is stale"
        }
    }
}

if ($intentGateReasons.Count -gt 0) {
    $scanApplyAllowed = $false
    $manualApplyAllowed = $false
    Write-Host "Apply was blocked."
    foreach ($reason in $intentGateReasons) {
        Write-Host "  $reason"
    }
    Write-Host "Next steps:"
    Write-Host "  1. Review the signoff pack and update the intent file."
    Write-Host "  2. Re-run this wrapper with the same apply flags and a valid -IntentFile."
}
elseif ($ApplyScanPromotion -or $ApplyPromotion) {
    if ($ApplyScanPromotion) {
        $scanApplyArgs = @($scanPromotionArgs | Where-Object { $_ -ne "--plan-only" })
        $scanApplyArgs += "--apply"
        $scanApplyArgs += "--archive-dir"
        $scanApplyArgs += $ScanArchiveDir
        $scanApplyArgs += "--receipt-out"
        $scanApplyArgs += $ScanReceiptOut
        if ($Overwrite) {
            $scanApplyArgs += "--overwrite"
        }
        $scanPromotionExit = Invoke-AppPython -Arguments $scanApplyArgs
        Write-Host "  $ScanReceiptOut"
        Write-Host "  $scanPromotionReceiptMd"
    }
    if ($ApplyPromotion -and (Test-ManualDraftsReady)) {
        $manualApplyArgs = @(
            "-m", "vuln_pipeline.cli.manual_promotion",
            "--working-dir", $WorkingDir,
            "--live-manual-dir", $LiveManualDir,
            "--output-dir", $PromotionOutputDir,
            "--apply",
            "--backup-dir", $PromotionBackupDir,
            "--receipt-out", $PromotionReceiptOut
        )
        if ($Overwrite) {
            $manualApplyArgs += "--overwrite"
        }
        $manualPromotionExit = Invoke-AppPython -Arguments $manualApplyArgs
        Write-Host "  $PromotionReceiptOut"
        Write-Host "  $promotionReceiptMd"
    }
}

$preflightArgs = @{
    RunId = $RunId
    OutputBase = $OutputBase
}
if ($PSBoundParameters.ContainsKey("CustomerBundle")) { $preflightArgs["CustomerBundle"] = $CustomerBundle }
if ($PSBoundParameters.ContainsKey("BrandingFile")) { $preflightArgs["BrandingFile"] = $BrandingFile }
if ($PSBoundParameters.ContainsKey("ReadinessPolicy")) { $preflightArgs["ReadinessPolicy"] = $ReadinessPolicy }
if ($StageRealInputs) { $preflightArgs["StageRealInputs"] = $true }
if ($RequirePptx) { $preflightArgs["RequirePptx"] = $true }

& (Join-Path $PSScriptRoot "run_preflight.ps1") @preflightArgs
$preflightExit = $LASTEXITCODE

$rehearsalArgs = @{
    RunId = $RunId
    OutputBase = $OutputBase
}
if ($PSBoundParameters.ContainsKey("CustomerBundle")) { $rehearsalArgs["CustomerBundle"] = $CustomerBundle }
if ($PSBoundParameters.ContainsKey("BrandingFile")) { $rehearsalArgs["BrandingFile"] = $BrandingFile }
if ($PSBoundParameters.ContainsKey("ReadinessPolicy")) { $rehearsalArgs["ReadinessPolicy"] = $ReadinessPolicy }
if ($StageRealInputs) { $rehearsalArgs["StageRealInputs"] = $true }
if ($RequirePptx) { $rehearsalArgs["RequirePptx"] = $true }

& (Join-Path $PSScriptRoot "run_real_rehearsal.ps1") @rehearsalArgs
$rehearsalExit = $LASTEXITCODE

$comparisonJson = Join-Path $reportDataDir "rerun_comparison.json"
$comparisonMd = Join-Path $reportDataDir "rerun_comparison.md"
if ($resolvedPreviousRunRoot) {
    $comparisonExit = Invoke-AppPython -Arguments @(
        "-m", "vuln_pipeline.cli.rerun_comparison",
        "--current-run-root", $runRoot,
        "--previous-run-root", $resolvedPreviousRunRoot,
        "--manual-dir", $LiveManualDir,
        "--output-dir", $reportDataDir
    )
}
else {
    $comparisonExit = 0
    Write-Host "Comparison step skipped because no previous run was provided."
}

$inputPreflight = Join-Path $reportDataDir "input_preflight.json"
$selectionJson = Join-Path $reportDataDir "real_input_selection.json"
$triageJson = Join-Path $reportDataDir "post_run_triage.json"
$triageMd = Join-Path $reportDataDir "post_run_triage.md"
$triageCsv = Join-Path $reportDataDir "post_run_triage_worklist.csv"
$manualValidationJson = Join-Path $reportDataDir "manual_validation.json"
$manualValidationMd = Join-Path $reportDataDir "manual_validation.md"
$releaseReadiness = Join-Path $reportDataDir "release_readiness.json"
$submissionGate = Join-Path $reportDataDir "submission_gate.json"
$reviewClosure = Join-Path $reportDataDir "review_closure_status.json"
$finalManifest = Join-Path $runRoot "delivery\final_delivery_manifest.json"
$customerZip = Get-ChildItem -Path (Join-Path $runRoot "delivery") -Filter "customer_submission_*.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$internalZip = Get-ChildItem -Path (Join-Path $runRoot "delivery") -Filter "internal_archive_*.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$null = Write-OperatorCase -CasePhase "post-run" -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot
$null = Invoke-EvidencePack -ResolvedWorkspaceRoot $resolvedWorkspaceRoot -ResolvedPreviousRunRoot $resolvedPreviousRunRoot -ResolvedIntentFile $resolvedIntentFile

Write-Host "Operator case artifacts:"
Write-Host "  $operatorCaseJson"
Write-Host "  $operatorCaseMd"
if ($bootstrapManifestJson) {
    Write-Host "Workspace bootstrap artifacts:"
    Write-Host "  $bootstrapManifestJson"
    Write-Host "  $bootstrapManifestMd"
}

Write-Host "Iteration artifacts:"
Write-Host "  $scanPromotionPlanJson"
Write-Host "  $scanPromotionPlanMd"
Write-Host "  $liveScanInventoryJson"
Write-Host "  $liveScanInventoryMd"
if ($scanApplyAllowed) {
    Write-Host "  $ScanReceiptOut"
    Write-Host "  $scanPromotionReceiptMd"
}
Write-Host "  $promotionPlanJson"
Write-Host "  $promotionPlanMd"
if ($manualApplyAllowed) {
    Write-Host "  $PromotionReceiptOut"
    Write-Host "  $promotionReceiptMd"
}
Write-Host "  $inputPreflight"
Write-Host "  $selectionJson"
Write-Host "  $triageJson"
Write-Host "  $triageMd"
Write-Host "  $triageCsv"
Write-Host "  $manualValidationJson"
Write-Host "  $manualValidationMd"
Write-Host "  $comparisonJson"
Write-Host "  $comparisonMd"
Write-Host "  $signoffReviewJson"
Write-Host "  $signoffReviewMd"
Write-Host "  $signoffIntentTemplate"
Write-Host "  $intentValidationJson"
Write-Host "  $intentValidationMd"
Write-Host "  $evidencePackJson"
Write-Host "  $evidencePackMd"
Write-Host "  $releaseReadiness"
Write-Host "  $submissionGate"
Write-Host "  $finalManifest"
Write-Host "  $reviewClosure"
if ($customerZip) { Write-Host "  $($customerZip.FullName)" } else { Write-Host "  $(Join-Path $runRoot 'delivery\customer_submission_*.zip')" }
if ($internalZip) { Write-Host "  $($internalZip.FullName)" } else { Write-Host "  $(Join-Path $runRoot 'delivery\internal_archive_*.zip')" }

if ($scanPromotionExit -ne 0 -and $scanApplyAllowed) { exit $scanPromotionExit }
if ($manualPromotionExit -ne 0 -and $manualApplyAllowed) { exit $manualPromotionExit }
if ($rehearsalExit -ne 0) { exit $rehearsalExit }
if ($preflightExit -ne 0) { exit $preflightExit }
exit $comparisonExit
