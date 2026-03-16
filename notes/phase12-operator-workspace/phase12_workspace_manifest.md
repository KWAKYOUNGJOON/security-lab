# Phase12 Workspace Manifest

- status: `bootstrapped`
- workspace_root: `D:\취약점 진단\notes\phase12-operator-workspace`
- repo_workspace_root: `D:\취약점 진단`
- live_real_dir: `D:\취약점 진단\data\inputs\real`
- live_manual_dir: `D:\취약점 진단\data\inputs\real\manual`
- seed_mode: `from_templates`

## Directories
- workspace_root: `D:\취약점 진단\notes\phase12-operator-workspace`
- incoming_root: `D:\취약점 진단\notes\phase12-operator-workspace\incoming`
- incoming_burp: `D:\취약점 진단\notes\phase12-operator-workspace\incoming\burp`
- incoming_nuclei: `D:\취약점 진단\notes\phase12-operator-workspace\incoming\nuclei`
- incoming_httpx: `D:\취약점 진단\notes\phase12-operator-workspace\incoming\httpx`
- manual_drafts: `D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts`
- receipts: `D:\취약점 진단\notes\phase12-operator-workspace\receipts`
- artifacts: `D:\취약점 진단\notes\phase12-operator-workspace\artifacts`
- report_data: `D:\취약점 진단\notes\phase12-operator-workspace\report_data`

## Empty Required Items
- incoming/burp is empty; operator must drop a real Burp export into the non-live workspace before planning scan promotion.
- incoming/nuclei is empty; operator must drop a real nuclei export into the non-live workspace before planning scan promotion.
- incoming/httpx is empty; operator must drop a real httpx export into the non-live workspace before planning scan promotion.
- override_working.yaml: actionable list `overrides` currently contains `0` approved rows.
- suppression_working.yaml: actionable list `suppressions` currently contains `0` approved rows.
- review_resolution_working.yaml: actionable list `review_resolutions` currently contains `0` approved rows.

## Operator Confirmation Needed
- Confirm which real incoming exports should be promoted; the bootstrap does not inspect or copy live scan files.
- Keep live real directories and this non-live workspace separate. Bootstrap never writes into data\inputs\real.
- Review draft_candidates manually and copy only approved rows into overrides/suppressions/review_resolutions.

## Recommended Next Commands
- 1. Drop real Burp/nuclei/httpx exports into the non-live incoming directories under `D:\취약점 진단\notes\phase12-operator-workspace\incoming`. Do not place templates or dummy files there.
- 2. `python -m vuln_pipeline.cli.scan_input_promotion --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" --live-root "D:\취약점 진단\data\inputs\real" --output-dir "D:\취약점 진단\outputs\runs\phase12-first-real-convergence\report_data\scan_promotion" --plan-only`
- 3. `python -m vuln_pipeline.cli.manual_promotion --working-dir "D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts" --live-manual-dir "D:\취약점 진단\data\inputs\real\manual" --output-dir "D:\취약점 진단\outputs\runs\phase12-first-real-convergence\report_data\manual_promotion" --plan-only`
- 4. `powershell -ExecutionPolicy Bypass -File "D:\취약점 진단\app\vuln-pipeline\scripts\run_phase12_iteration.ps1" -RunId "phase12-first-real-convergence" -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace"`
- 5. `python -m vuln_pipeline.cli.phase12_apply_signoff review --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" --run-id "phase12-first-real-convergence" --output-dir "D:\취약점 진단\outputs\runs\phase12-first-real-convergence\report_data"`
- 6. Read `D:\취약점 진단\notes\phase12-operator-workspace\phase12_workspace_manifest.md` and the signoff review before any live apply step.

## Seed Summary
- review_row_count: `0`
- unresolved_row_count: `0`
- written_file: `D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts\override_working.yaml`
- written_file: `D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts\suppression_working.yaml`
- written_file: `D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts\review_resolution_working.yaml`
- written_file: `D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts\bootstrap_worklist.md`
