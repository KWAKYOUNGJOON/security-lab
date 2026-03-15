[CmdletBinding()]
param(
    [string]$WorkspaceRoot,
    [string]$CustomerBundle,
    [string]$BrandingFile,
    [string]$ReadinessPolicy,
    [string]$OverrideFile,
    [string]$SuppressionFile,
    [string]$ReviewResolutionFile,
    [string]$JsonOut,
    [string]$MarkdownOut
)

$appRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $PSBoundParameters.ContainsKey("WorkspaceRoot")) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
}
if (-not $PSBoundParameters.ContainsKey("CustomerBundle")) {
    $CustomerBundle = Join-Path $appRoot "configs\customer_bundles\default_customer_release.yaml"
}
if (-not $PSBoundParameters.ContainsKey("BrandingFile")) {
    $BrandingFile = Join-Path $appRoot "configs\branding\customer_branding.yaml"
}

$command = @(
    "python", "-m", "vuln_pipeline.cli.real_input_readiness",
    "--workspace-root", $WorkspaceRoot,
    "--customer-bundle", $CustomerBundle,
    "--branding-file", $BrandingFile
)
if ($PSBoundParameters.ContainsKey("ReadinessPolicy")) { $command += @("--readiness-policy", $ReadinessPolicy) }
if ($PSBoundParameters.ContainsKey("OverrideFile")) { $command += @("--override-file", $OverrideFile) }
if ($PSBoundParameters.ContainsKey("SuppressionFile")) { $command += @("--suppression-file", $SuppressionFile) }
if ($PSBoundParameters.ContainsKey("ReviewResolutionFile")) { $command += @("--review-resolution-file", $ReviewResolutionFile) }
if ($PSBoundParameters.ContainsKey("JsonOut")) { $command += @("--json-out", $JsonOut) }
if ($PSBoundParameters.ContainsKey("MarkdownOut")) { $command += @("--markdown-out", $MarkdownOut) }

Push-Location $appRoot
try {
    & $command[0] $command[1..($command.Length - 1)]
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
