# Phase12 Final Real Gate

- status: `no_live_apply_detected`
- run_id: `manual-explicit-repro`
- run_root: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro`
- rehearsal_allowed: `False`
- real_explicit_proof_status: `operator-confirmation-needed`

## Hard Fact Summary
- fresh_preflight_generated: `True`
- preflight_status: `blocked`
- preflight_blocker_count: `1`
- readiness_status: `blocked`
- readiness_blocker_count: `1`
- manual_sources_ready: `False`
- apply_detected: `False`
- signoff_review_status: `missing`
- intent_validation_status: `missing`
- apply_reconciliation_status: `no_apply_detected`

## Current Live Active Files
- burp: active_file=`None` eligible_file_count=`0`
- nuclei: active_file=`None` eligible_file_count=`0`
- httpx: active_file=`None` eligible_file_count=`0`

## Current Preflight Selected Files
- burp: preflight_selected=`None` real_input_selection_selected=`None`
- nuclei: preflight_selected=`None` real_input_selection_selected=`None`
- httpx: preflight_selected=`None` real_input_selection_selected=`None`

## Promotion Receipt Convergence
- burp: receipt_present=`False` current_live_matches_receipt_target=`False` archive_all_present=`True`
- nuclei: receipt_present=`False` current_live_matches_receipt_target=`False` archive_all_present=`True`
- httpx: receipt_present=`False` current_live_matches_receipt_target=`False` archive_all_present=`True`
- override_file: manual_source=`real_explicit` proof_status=`operator-confirmation-needed` receipt_present=`False` backup_present=`False`
- suppression_file: manual_source=`real_explicit` proof_status=`operator-confirmation-needed` receipt_present=`False` backup_present=`False`
- review_resolution_file: manual_source=`real_explicit` proof_status=`operator-confirmation-needed` receipt_present=`False` backup_present=`False`

## Remaining Blockers
- input_preflight status is `blocked`
- input_preflight blocker_count is `1`
- real_input_readiness is blocked
- real_input_readiness blocker_count is `1`
- input_preflight.manual_sources_ready is false
- manual_validation indicates the live manual context is not ready for rerun
- burp: live eligible_file_count is `0`
- burp: current live active file is missing
- nuclei: live eligible_file_count is `0`
- nuclei: current live active file is missing
- httpx: live eligible_file_count is `0`
- httpx: current live active file is missing
- override_file: current live manual file is missing
- suppression_file: current live manual file is missing
- review_resolution_file: current live manual file is missing

## Warnings
- phase12_signoff_review.json is missing
- no live apply receipt was detected for this run

## Proof Of real_explicit Or Why Not Proven
- override_file: manual_source could not be proven from current artifacts
- suppression_file: manual_source could not be proven from current artifacts
- review_resolution_file: manual_source could not be proven from current artifacts

## Hard Fact / Inference Boundary
- hard_facts: current live files, fresh preflight selection, receipt path/hash, manual_source fields, archive/backup existence
- inference: overall rehearsal_allowed decision and proof status rollup

## Exact Next Commands
- rehearsal_command: `powershell -ExecutionPolicy Bypass -File "D:\취약점 진단\app\vuln-pipeline\scripts\run_phase12_iteration.ps1" -RunId "manual-explicit-repro" -OutputBase "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs" -LiveRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real" -GenerateRealGate -RequireRealGateForRehearsal -RefreshPreflightBeforeGate -WorkspaceRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace" -CustomerBundle "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml" -BrandingFile "D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml" -ReadinessPolicy "D:\취약점 진단\app\vuln-pipeline\configs\readiness\customer_release.yaml"`
- missing_input_fix_command: `powershell -ExecutionPolicy Bypass -File "D:\취약점 진단\app\vuln-pipeline\scripts\run_phase12_iteration.ps1" -RunId "manual-explicit-repro" -OutputBase "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs" -LiveRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real" -GenerateRealGate -RequireRealGateForRehearsal -RefreshPreflightBeforeGate -WorkspaceRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace" -CustomerBundle "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml" -BrandingFile "D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml" -ReadinessPolicy "D:\취약점 진단\app\vuln-pipeline\configs\readiness\customer_release.yaml" -StopAfterRealGate`
- rollback_plan_command: `powershell -ExecutionPolicy Bypass -File "D:\취약점 진단\app\vuln-pipeline\scripts\run_phase12_rollback.ps1" -RunRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro" -WorkspaceRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace" -LiveRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real"`
