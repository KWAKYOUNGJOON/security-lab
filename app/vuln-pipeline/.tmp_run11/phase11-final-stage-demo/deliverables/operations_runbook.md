# Operations Runbook

- run_root: `.tmp_run11\phase11-final-stage-demo`
- run_id: `phase11-final-stage-demo`

## Input Preparation
- Real Burp input directory: `D:\취약점 진단\data\inputs\real\burp`
- Real Nuclei input directory: `D:\취약점 진단\data\inputs\real\nuclei`
- Real httpx input directory: `D:\취약점 진단\data\inputs\real\httpx`
- Real manual input directory: `D:\취약점 진단\data\inputs\real\manual`
- Burp input directory: `D:\취약점 진단\data\inputs\burp`
- Nuclei input directory: `D:\취약점 진단\data\inputs\nuclei`
- httpx input directory: `D:\취약점 진단\data\inputs\httpx`
- Manual input directory: `D:\취약점 진단\data\inputs\manual`

## Preflight Order
1. Run the preflight check and confirm `report_data\input_preflight.json` is `ready` or expected `warning`.
2. Verify the selected input files are not sample or test fixtures.
3. Confirm manual override, suppression, and review resolution files if they are expected for this release.

## Review Flow
1. Apply override file: `tests\fixtures\realish\override_realish.yaml`
2. Apply suppression file: `tests\fixtures\realish\suppressions.yaml`
3. Apply review resolution file: `tests\fixtures\realish\review_resolution.yaml`
4. Confirm review queue is resolved before customer final packaging.

## Customer Final
- report template: `default_customer`
- deliverable profile: `customer_pack`
- branding file: `D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml`
1. Run package output with finalize-delivery when readiness is acceptable.
2. Check submission gate, privacy audit, and final submission check before handing off the customer ZIP.

## Internal Archive
1. Use `--archive-only` when only the internal archive needs regeneration.
2. Confirm `delivery\internal_archive_<version>.zip` is refreshed and `report_data\archive_only_manifest.json` is present.
3. Confirm customer submission ZIP and customer package manifests were intentionally skipped.

## Troubleshooting
- Current preflight status: `ready`
- If preflight is blocked, replace sample, zero-byte, or unsupported files before rerunning.
- If privacy audit fails, remove internal-only outputs from the customer package whitelist.
- If PPTX capability is blocked, install `python-pptx` or proceed with fallback policy.
