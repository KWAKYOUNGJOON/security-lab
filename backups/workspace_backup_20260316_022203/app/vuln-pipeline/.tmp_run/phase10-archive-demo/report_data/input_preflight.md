# Input Preflight

- status: `ready`
- auto_select_real_inputs: `False`
- selected_run_input_count: `3`
- warning_count: `0`
- blocker_count: `0`

## Tool Checks
### burp
- selection_source: `explicit`
- configured_directory: `D:\취약점 진단\data\inputs\burp`
- eligible_file_count_in_directory: `1`
- `tests\fixtures\realish\burp_complex.xml` | real_candidate=True | size=1432 | lines=36 | modified=2026-03-15T01:52:48+00:00
### nuclei
- selection_source: `explicit`
- configured_directory: `D:\취약점 진단\data\inputs\nuclei`
- eligible_file_count_in_directory: `1`
- `tests\fixtures\realish\nuclei_rich.jsonl` | real_candidate=True | size=2427 | lines=5 | modified=2026-03-15T01:52:48+00:00
### httpx
- selection_source: `explicit`
- configured_directory: `D:\취약점 진단\data\inputs\httpx`
- eligible_file_count_in_directory: `1`
- `tests\fixtures\realish\httpx_rich.jsonl` | real_candidate=True | size=1042 | lines=4 | modified=2026-03-15T01:52:48+00:00

## Manual Inputs
- override_file: `present` (tests\fixtures\realish\override_realish.yaml)
- suppression_file: `present` (tests\fixtures\realish\suppressions.yaml)
- review_resolution_file: `present` (tests\fixtures\realish\review_resolution.yaml)
