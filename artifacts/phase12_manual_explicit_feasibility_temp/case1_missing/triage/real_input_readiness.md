# Real Input Readiness

- status: `blocked`
- selection_status: `incomplete`
- real_scan_inputs_ready: `False`
- manual_sources_ready: `False`
- blocker_count: `1`
- warning_count: `3`

## Config Checks
- customer_bundle: exists=`True` | effective_path=`D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml`
- branding_file: exists=`True` | effective_path=`D:\취약점 진단\app\vuln-pipeline\configs\branding\customer_branding.yaml`
- readiness_policy: exists=`True` | effective_path=`D:\취약점 진단\app\vuln-pipeline\configs\readiness\customer_release.yaml`

## Tool Selection
### burp
- selected_by_code: `None`
- source_priority: `real`
- reason: `no_eligible_candidates`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\burp` | exists=`True` | visible_file_count=`0` | selected_by_code=`True`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\burp` | exists=`False` | visible_file_count=`0` | selected_by_code=`False`
- candidate: none
### nuclei
- selected_by_code: `None`
- source_priority: `real`
- reason: `no_eligible_candidates`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\nuclei` | exists=`True` | visible_file_count=`0` | selected_by_code=`True`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\nuclei` | exists=`False` | visible_file_count=`0` | selected_by_code=`False`
- candidate: none
### httpx
- selected_by_code: `None`
- source_priority: `real`
- reason: `no_eligible_candidates`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\httpx` | exists=`True` | visible_file_count=`0` | selected_by_code=`True`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\httpx` | exists=`False` | visible_file_count=`0` | selected_by_code=`False`
- candidate: none

## Manual Support
### override_file
- effective_execution_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_override.yaml`
- manual_source: `real_explicit`
- legacy_default: `False`
- live_manual_source_ready: `False`
- auto_selected_support_path: `None`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual` | exists=`True` | visible_file_count=`0` | selected_by_code=`False`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual` | exists=`True` | visible_file_count=`3` | selected_by_code=`True`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\review_resolution.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`False` | final_selected=`False` | exclusion_reason=`name_pattern_mismatch`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\suppressions.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`False` | final_selected=`False` | exclusion_reason=`name_pattern_mismatch`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\sample_override.yaml` | extension_ok=`True` | name_pattern_ok=`True` | excluded_name=`True` | final_selected=`False` | exclusion_reason=`excluded_name`
### suppression_file
- effective_execution_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_suppressions.yaml`
- manual_source: `real_explicit`
- legacy_default: `False`
- live_manual_source_ready: `False`
- auto_selected_support_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\suppressions.yaml`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual` | exists=`True` | visible_file_count=`0` | selected_by_code=`False`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual` | exists=`True` | visible_file_count=`3` | selected_by_code=`True`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\review_resolution.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`False` | final_selected=`False` | exclusion_reason=`name_pattern_mismatch`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\suppressions.yaml` | extension_ok=`True` | name_pattern_ok=`True` | excluded_name=`False` | final_selected=`True` | exclusion_reason=`selected_latest_eligible`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\sample_override.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`True` | final_selected=`False` | exclusion_reason=`excluded_name,name_pattern_mismatch`
### review_resolution_file
- effective_execution_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual\customer_review_resolution.yaml`
- manual_source: `real_explicit`
- legacy_default: `False`
- live_manual_source_ready: `False`
- auto_selected_support_path: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\review_resolution.yaml`
- directory[real]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\real\manual` | exists=`True` | visible_file_count=`0` | selected_by_code=`False`
- directory[legacy_fallback]: path=`D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual` | exists=`True` | visible_file_count=`3` | selected_by_code=`True`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\review_resolution.yaml` | extension_ok=`True` | name_pattern_ok=`True` | excluded_name=`False` | final_selected=`True` | exclusion_reason=`selected_latest_eligible`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\suppressions.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`False` | final_selected=`False` | exclusion_reason=`name_pattern_mismatch`
- candidate[legacy_fallback]: `D:\취약점 진단\artifacts\phase12_manual_explicit_feasibility_temp\workspace\data\inputs\manual\sample_override.yaml` | extension_ok=`True` | name_pattern_ok=`False` | excluded_name=`True` | final_selected=`False` | exclusion_reason=`excluded_name,name_pattern_mismatch`

## Live Scan Inventory
- status: `warning`
- active_valid_tool_count: `0`
- operational_goal_met: `False`
- live[burp]: active_file=`None` | eligible_file_count=`0`
- live[nuclei]: active_file=`None` | eligible_file_count=`0`
- live[httpx]: active_file=`None` | eligible_file_count=`0`

## Blockers
- real scan inputs are not ready

## Warnings
- override_file: manual input file not found
- suppression_file: manual input file not found
- review_resolution_file: manual input file not found
