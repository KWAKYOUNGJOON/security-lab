[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [string]$OverrideFile = "D:\취약점 진단\data\inputs\manual\sample_override.yaml",
    [string]$SuppressionFile = "D:\취약점 진단\data\inputs\manual\suppressions.yaml",
    [string]$ReviewResolutionFile = "D:\취약점 진단\data\inputs\manual\review_resolution.yaml",
    [string]$CustomerBundle = "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml",
    [string]$BrandingFile = "D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml",
    [string]$CompareToRun = "",
    [switch]$RequirePptx,
    [switch]$StageRealInputs
)

$command = @(
    "python", "-m", "vuln_pipeline.cli.main",
    "--run-id", $RunId,
    "--customer-bundle", $CustomerBundle,
    "--branding-file", $BrandingFile,
    "--override-file", $OverrideFile,
    "--suppression-file", $SuppressionFile,
    "--review-resolution-file", $ReviewResolutionFile,
    "--auto-select-real-inputs",
    "--package-output",
    "--release-candidate",
    "--finalize-delivery"
)
if ($CompareToRun) { $command += @("--compare-to-run", $CompareToRun) }
if ($RequirePptx) { $command += "--require-pptx" }
if ($StageRealInputs) { $command += "--stage-real-inputs" }
& $command[0] $command[1..($command.Length - 1)]
