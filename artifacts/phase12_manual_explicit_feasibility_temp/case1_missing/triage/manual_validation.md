# Manual Validation

- status: `invalid`
- manual_dir: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual`
- review_queue_reference_count: `0`
- note: Format validity and content assessment are reported separately. Empty actionable lists stay format-valid but still need operator judgment.

## execution_context
- description: Files actually referenced by the current run or preflight artifacts.
- required: `False`
- format_valid: `False`
- content_assessment: `human_review_required`

### override_file
- path: `None`
- format_status: `unavailable`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- issues: none
- warnings: none

### suppression_file
- path: `None`
- format_status: `unavailable`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- issues: none
- warnings: none

### review_resolution_file
- path: `None`
- format_status: `unavailable`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- issues: none
- warnings: none

## rerun_live_context
- description: Latest eligible files under the live real/manual directory that would be used on the next real rehearsal rerun.
- required: `True`
- format_valid: `False`
- content_assessment: `human_review_required`

### override_file
- path: `None`
- format_status: `missing`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- eligible_candidate_count: `0`
- issues:
  - Expected a live manual file but no eligible candidate was selected.
- warnings: none

### suppression_file
- path: `None`
- format_status: `missing`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- eligible_candidate_count: `0`
- issues:
  - Expected a live manual file but no eligible candidate was selected.
- warnings: none

### review_resolution_file
- path: `None`
- format_status: `missing`
- format_valid: `False`
- content_assessment: `human_review_required`
- actionable_count: `0`
- draft_candidate_count: `0`
- eligible_candidate_count: `0`
- issues:
  - Expected a live manual file but no eligible candidate was selected.
- warnings: none
