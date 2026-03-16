# Post-Run Triage

- run_root: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\outputs\runs\manual-explicit-repro`
- baseline_run_root: `D:\취약점 진단\outputs\runs\phase9-final-demo-v9`
- rollup_status: `blocked`
- blocked: `True`
- fail: `False`
- pass: `False`
- ready: `False`
- final_ready: `False`

## Hard Facts
- release_readiness_status: `missing`
- submission_gate_status: `missing`
- input_preflight_status: `missing`
- real_input_readiness_status: `missing`
- unresolved_review_items: `0`

## Missing Artifacts
- release_readiness
- submission_gate
- final_delivery_manifest
- review_closure_status
- real_input_selection
- review_queue

## Blockers
- none

## Gate Failures
- none

## Triage Hints
- [manual_validation] The live real/manual files are not structurally valid yet. Fix `manual_validation.md` findings before rerun.
- [rollup] The current run is blocked. Resolve blockers first, then rerun the rehearsal before expecting release artifacts.

## Baseline Comparison
- baseline_exists: `True`
- release_readiness_status: current=`missing` | baseline=`ready` | differs=`True`
- submission_gate_status: current=`missing` | baseline=`pass` | differs=`True`
- input_preflight_status: current=`missing` | baseline=`blocked` | differs=`True`
- real_input_readiness_status: current=`missing` | baseline=`blocked` | differs=`True`
- final_ready: current=`False` | baseline=`True` | differs=`True`
- unresolved_review_items: current=`0` | baseline=`0` | differs=`False`
- artifact `customer_submission_zip`: current=`False` | baseline=`True` | differs=`True`
- artifact `final_delivery_manifest`: current=`False` | baseline=`True` | differs=`True`
- artifact `input_preflight`: current=`False` | baseline=`True` | differs=`True`
- artifact `internal_archive_zip`: current=`False` | baseline=`True` | differs=`True`
- artifact `real_input_readiness`: current=`False` | baseline=`True` | differs=`True`
- artifact `real_input_selection`: current=`False` | baseline=`True` | differs=`True`
- artifact `real_rehearsal_blocked`: current=`True` | baseline=`False` | differs=`True`
- artifact `release_readiness`: current=`False` | baseline=`True` | differs=`True`
- artifact `release_readiness_summary`: current=`True` | baseline=`False` | differs=`True`
- artifact `review_closure_status`: current=`False` | baseline=`True` | differs=`True`
- artifact `review_queue`: current=`False` | baseline=`True` | differs=`True`
- artifact `submission_gate`: current=`False` | baseline=`True` | differs=`True`

## Worklist
- unresolved_count: `0`
- bucket_counts: `{}`
- suggested_action_bucket is a triage hint, not an automated approval/suppression/closeout decision.

| Work Item | Severity | Priority | Current Status | Suggested Bucket | Suggested Draft | Bucket Reason |
|---|---|---|---|---|---|---|
| - | - | - | - | no unresolved review items | - | - |

## Manual Validation
- status: `invalid`
- rerun_format_valid: `False`
- rerun_content_assessment: `human_review_required`
- manual_validation_json: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\case1_missing\triage\manual_validation.json`
- manual_validation_md: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\case1_missing\triage\manual_validation.md`
