# Input Preflight

- status: `blocked`
- auto_select_real_inputs: `False`
- selected_run_input_count: `3`
- warning_count: `0`
- blocker_count: `4`

## Tool Checks
### burp
- selection_source: `resolved_inputs`
- configured_directory: `D:\취약점 진단\data\inputs\burp`
- eligible_file_count_in_directory: `1`
- `D:\취약점 진단\data\inputs\burp\burp_sample.xml` | real_candidate=False | size=772 | lines=24 | modified=2026-03-15T01:08:56+00:00
  blockers: sample_or_test_file
### nuclei
- selection_source: `resolved_inputs`
- configured_directory: `D:\취약점 진단\data\inputs\nuclei`
- eligible_file_count_in_directory: `1`
- `D:\취약점 진단\data\inputs\nuclei\nuclei_sample.jsonl` | real_candidate=False | size=1059 | lines=3 | modified=2026-03-15T01:08:56+00:00
  blockers: sample_or_test_file
### httpx
- selection_source: `resolved_inputs`
- configured_directory: `D:\취약점 진단\data\inputs\httpx`
- eligible_file_count_in_directory: `1`
- `D:\취약점 진단\data\inputs\httpx\httpx_sample.jsonl` | real_candidate=False | size=560 | lines=3 | modified=2026-03-15T01:08:56+00:00
  blockers: sample_or_test_file

## Manual Inputs
- override_file: `present` (D:\취약점 진단\data\inputs\manual\sample_override.yaml)
- suppression_file: `present` (D:\취약점 진단\data\inputs\manual\suppressions.yaml)
- review_resolution_file: `present` (D:\취약점 진단\data\inputs\manual\review_resolution.yaml)

## Blockers
- burp: sample_or_test_file
- nuclei: sample_or_test_file
- httpx: sample_or_test_file
- real scan inputs are not ready
