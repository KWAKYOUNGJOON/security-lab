[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [string]$CustomerBundle = "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml",
    [string]$BrandingFile = "D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml",
    [switch]$RequirePptx
)

$command = @(
    "python", "-m", "vuln_pipeline.cli.main",
    "--run-id", $RunId,
    "--customer-bundle", $CustomerBundle,
    "--branding-file", $BrandingFile,
    "--check-pptx-capability"
)
if ($RequirePptx) { $command += "--require-pptx" }
& $command[0] $command[1..($command.Length - 1)]
