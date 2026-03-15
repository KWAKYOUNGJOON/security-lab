# Real Data Onboarding Checklist

- real_burp_dir: `D:\취약점 진단\data\inputs\real\burp`
- real_nuclei_dir: `D:\취약점 진단\data\inputs\real\nuclei`
- real_httpx_dir: `D:\취약점 진단\data\inputs\real\httpx`
- real_manual_dir: `D:\취약점 진단\data\inputs\real\manual`

## Naming Rules
- Do not place sample, fixture, test, or realish files in the real intake directories.
- Use stable customer or date-oriented filenames so the newest file is meaningful.

## Preflight Conditions
- current_preflight_status: `blocked`
- Confirm selected files are real, non-zero, supported, and not duplicate content.

## Manual Inputs
- override_file: `D:\취약점 진단\data\inputs\manual\sample_override.yaml`
- suppression_file: `D:\취약점 진단\data\inputs\manual\suppressions.yaml`
- review_resolution_file: `D:\취약점 진단\data\inputs\manual\review_resolution.yaml`

## Release Flow
- Run preflight first.
- Run customer final after review, suppression, and override validation.
- Use archive-only only when customer submission should remain untouched.

## PPTX
- require_pptx: `True`
- current_pptx_capability: `blocked`
