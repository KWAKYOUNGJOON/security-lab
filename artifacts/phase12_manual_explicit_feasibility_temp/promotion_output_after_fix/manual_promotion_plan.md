# Manual Promotion Plan

- status: `ready_for_review`
- working_dir: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_working`
- live_manual_dir: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live`
- output_dir: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_output_after_fix`
- review_queue_path: `None`
- material_change_file_count: `0`
- actionable_entry_count: `0`
- allow_empty_explicit_seed_requested: `True`
- empty_explicit_seed_eligible: `True`

## Blockers
- none

## Warnings
- Staged promotion candidates are structurally valid, but content still needs operator review before rerun.
- No actionable changes relative to the existing live files were detected.

## File Plan
### override_file
- status: `ready_to_apply`
- working_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_working\override_working.yaml`
- target_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_override.yaml`
- staged_candidate_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_output_after_fix\customer_override_candidate.yaml`
- existing_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_override.yaml`
- actionable_count: `0`
- draft_candidate_count: `0`
- diff: added=`0` removed=`0` changed=`0`
### suppression_file
- status: `ready_to_apply`
- working_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_working\suppression_working.yaml`
- target_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_suppressions.yaml`
- staged_candidate_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_output_after_fix\customer_suppressions_candidate.yaml`
- existing_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_suppressions.yaml`
- actionable_count: `0`
- draft_candidate_count: `0`
- diff: added=`0` removed=`0` changed=`0`
### review_resolution_file
- status: `ready_to_apply`
- working_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_working\review_resolution_working.yaml`
- target_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_review_resolution.yaml`
- staged_candidate_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_output_after_fix\customer_review_resolution_candidate.yaml`
- existing_live_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\promotion_live\customer_review_resolution.yaml`
- actionable_count: `0`
- draft_candidate_count: `0`
- diff: added=`0` removed=`0` changed=`0`

## Candidate Validation
- format_valid: `True`
- content_assessment: `human_review_required`

## Guidance
- draft_candidates are informational only and were not promoted automatically.
- Only the top-level actionable lists from the reviewed working drafts were staged.
- Apply mode stays blocked when staged candidates fail validation or when existing live files have unexpected structure.
