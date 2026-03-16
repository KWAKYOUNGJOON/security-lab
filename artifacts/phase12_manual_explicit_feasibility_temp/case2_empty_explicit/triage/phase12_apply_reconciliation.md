# Phase12 Apply Reconciliation

- status: `no_apply_detected`
- run_id: `manual-explicit-repro`
- run_root: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro`
- apply_detected: `False`
- scan_promotion_applied: `False`
- manual_promotion_applied: `False`
- signoff_review_status: `missing`
- intent_validation_status: `missing`

## Hard Facts
- workspace_root: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace`
- previous_run_root: `None`
- live_root: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real`
- live_manual_dir: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual`

## Readiness Blockers
- none

## Missing Artifacts
- phase12_operator_case.json
- post_run_triage.json
- real_input_selection.json
- input_preflight.json
- manual_validation.json
- phase12_apply_intent.json

## Scan Reconciliation
### burp
- receipt_present: `False`
- receipt_source_path: `None`
- planned_target_path: `None`
- current_live_active_path: `None`
- preflight_selected_path: `None`
- planned_target_matches_current_live: `False`
- current_live_matches_preflight_selected: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- archive_ready: `True`
### nuclei
- receipt_present: `False`
- receipt_source_path: `None`
- planned_target_path: `None`
- current_live_active_path: `None`
- preflight_selected_path: `None`
- planned_target_matches_current_live: `False`
- current_live_matches_preflight_selected: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- archive_ready: `True`
### httpx
- receipt_present: `False`
- receipt_source_path: `None`
- planned_target_path: `None`
- current_live_active_path: `None`
- preflight_selected_path: `None`
- planned_target_matches_current_live: `False`
- current_live_matches_preflight_selected: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- archive_ready: `True`

## Manual Reconciliation
### override_file
- receipt_present: `False`
- current_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_override.yaml`
- current_live_exists: `True`
- current_live_hash: `584a0bd345157598223aa1ae1dd7a510e0750ff585e5a7e2c7c4842a3c15d9d1`
- receipt_after_path: `None`
- current_live_matches_receipt_path: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- backup_ready: `False`
### suppression_file
- receipt_present: `False`
- current_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_suppressions.yaml`
- current_live_exists: `True`
- current_live_hash: `f0775c0f3b2a317161d099c06521efeda35b0c27603e313318ebb2dc786bd0b2`
- receipt_after_path: `None`
- current_live_matches_receipt_path: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- backup_ready: `False`
### review_resolution_file
- receipt_present: `False`
- current_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_review_resolution.yaml`
- current_live_exists: `True`
- current_live_hash: `c85bb888362738b47a1e058e064d9936f6d1e2504b98c65592b485cd81addfcd`
- receipt_after_path: `None`
- current_live_matches_receipt_path: `False`
- current_live_hash_matches_receipt_after_hash: `False`
- backup_ready: `False`

## Inference
- manual_source_real_explicit_assessment: `operator-confirmation-needed`
- manual_source could not be proven from current artifacts.

## Suggestions
- rerun_command: `powershell -ExecutionPolicy Bypass -File "D:\취약점 진단\app\vuln-pipeline\scripts\run_phase12_iteration.ps1" -RunId "manual-explicit-repro" -WorkspaceRoot "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace" -GenerateSignoffReview`
- rollback_plan_command: `python -m vuln_pipeline.cli.phase12_rollback --run-root "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro" --workspace-root "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace" --live-root "D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real" --plan-only`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\phase12_signoff_review.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\phase12_apply_intent.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\phase12_apply_intent_validation.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\case2_empty_explicit\triage\scan_promotion\scan_input_promotion_receipt.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\case2_empty_explicit\triage\manual_promotion\manual_promotion_receipt.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\input_preflight.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\real_input_selection.json`
- inspect: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro\report_data\manual_validation.json`
