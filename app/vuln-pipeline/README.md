# vuln-pipeline

Python-based local vulnerability parsing and reporting pipeline for Burp XML, nuclei JSON/JSONL, and httpx JSONL.

현재 이 저장소에서 재현 기준이 되는 메인 구현체는 `app/vuln-pipeline`이다. 승인 전 실데이터 준비보다 fixture/mock 기반 보고서 자동화 E2E 재현성을 먼저 고정한다.

## Repro Contract

- Python: `3.11+`
- 작업 디렉터리: `app/vuln-pipeline`
- 패키지 소스: `src/vuln_pipeline`
- 로컬 import 호환 래퍼: `vuln_pipeline/__init__.py`
- 기본 smoke E2E: `python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py`
- 전체 테스트: `python -m pytest -q`
- CI smoke job: `.github/workflows/vuln-pipeline-must-pass.yml`

`pytest`는 저장소 checkout 상태에서도 동작하도록 `tests/conftest.py`에서 로컬 `src` 레이아웃을 부트스트랩한다. CLI 사용이나 일반 개발 환경에서는 editable install을 권장한다.

Default output root:
- `D:\취약점 진단\outputs\runs\<run_id>\`

Constraints:
- Do not modify `D:\취약점 진단\reference`
- Windows path conventions are the baseline
- Existing CLI, batch ingest, override, suppression, review queue, run diff, QA metrics, Markdown/DOCX, package-output, deliverables, readiness, release candidate, final delivery, customer/internal package split, branding, submission gate, preflight, runbook, privacy audit, archive-only, and PPTX capability flows remain supported

## Install

```powershell
cd D:\취약점 진단\app\vuln-pipeline
python -m pip install -e .
```

Linux/macOS 예시:

```bash
cd app/vuln-pipeline
python -m pip install -e .
python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py
```

Dependencies:
- `python-docx`
- `PyYAML`
- `python-pptx`

fixture 기반 재현만 필요하면 editable install 없이 `python -m pytest -q`로도 동작해야 한다.

## Encoding Troubleshooting

README and generated Markdown files are stored as UTF-8. If Korean text looks broken in Windows PowerShell, that is usually a console display issue rather than a file corruption issue.

Recommended check:

```powershell
chcp 65001
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
Get-Content .\README.md -Encoding utf8
```

Guidance:
- Keep docs saved as UTF-8.
- Use `Get-Content -Encoding utf8` when checking generated Markdown from PowerShell.
- If the file opens correctly in an editor but not in the console, treat it as a console encoding issue.

## Input Layout

Real input directories:
- `D:\취약점 진단\data\inputs\real\burp`
- `D:\취약점 진단\data\inputs\real\nuclei`
- `D:\취약점 진단\data\inputs\real\httpx`
- `D:\취약점 진단\data\inputs\real\manual`

Legacy or mixed input directories:
- `D:\취약점 진단\data\inputs\burp`
- `D:\취약점 진단\data\inputs\nuclei`
- `D:\취약점 진단\data\inputs\httpx`
- `D:\취약점 진단\data\inputs\manual`

`--auto-select-real-inputs` behavior:
1. Check `data\inputs\real\*` first.
2. If the real directory for that tool is empty, fall back to the legacy directory.
3. Continue excluding names containing `sample`, `fixture`, `test`, or `realish`.

## Preflight and Intake

실데이터 전 단계에서는 `--preflight-only`와 fixture smoke E2E를 우선 사용한다. 실제 입력 디렉터리 연결이나 스테이징은 승인 이후 별도 작업으로 취급한다.

Generated outputs:
- `report_data\input_preflight.json`
- `report_data\input_preflight.md`
- `report_data\input_intake_manifest.json`
- `report_data\input_hashes.json`

Recorded intake fields:
- `source_path`
- `selected_for_run`
- `rejection_reason`
- `detected_tool`
- `file_size`
- `modified_time`
- `sha256`
- `sample_like`
- `copied_or_referenced`
- `snapshot_path`

If `--stage-real-inputs` is used, selected files are copied into:
- `outputs\runs\<run_id>\input_snapshot\`

Large files fall back to reference-only mode instead of hard failure.

Preflight only example:

```powershell
python -m vuln_pipeline.cli.main `
  --run-id phase11-real-preflight `
  --auto-select-real-inputs `
  --preflight-only
```

## Customer Bundle

Bundle file:
- `configs\customer_bundles\default_customer_release.yaml`

Supported bundle values:
- `branding_file`
- `report_profile`
- `report_template`
- `deliverable_profile`
- `readiness_policy`
- `remediation_policy_dir`
- `require_pptx`
- `package_policy`

Recorded output:
- `report_data\applied_bundle_config.json`

Priority:
1. Explicit CLI option
2. Bundle value
3. Parser default

## Privacy Audit

Generated outputs:
- `report_data\customer_package_audit.json`
- `report_data\customer_package_audit.md`
- `report_data\customer_package_audit_findings.jsonl`

Audit scope:
- customer ZIP internal entry paths
- packaged file names and relative paths
- Markdown/JSON/TXT content keyword scanning

Forbidden examples:
- `review_queue`
- `override_template`
- `analyst_handoff`
- `decision trace`
- `raw artifacts`
- `internal_archive`
- `mapping_decisions`
- `scoring_decisions`
- `cluster_decisions`
- `suppression_decisions`

## Archive Only

Use `--archive-only` when only the internal archive should be regenerated.

Outputs:
- `delivery\internal_archive_<version>.zip`
- `report_data\archive_only_manifest.json`

The archive-only manifest records:
- `source_run_id`
- `reused_artifacts`
- `regenerated_files`
- `skipped_customer_outputs`

## PPTX Capability

Generated outputs:
- `report_data\pptx_capability.json`
- `report_data\pptx_capability.md`

Fields:
- `dependency_found`
- `import_check`
- `expected_output_path`
- `fallback_path`
- `install_hint`
- `require_pptx_would_block`

## Runbooks and Checklists

Each operational run writes:
- `deliverables\operations_runbook.md`
- `deliverables\release_runbook.md`
- `deliverables\final_submission_check.md`
- `deliverables\real_data_onboarding_checklist.md`

## PowerShell Wrappers

Scripts:
- `scripts\run_preflight.ps1`
- `scripts\run_customer_final.ps1`
- `scripts\run_internal_archive.ps1`
- `scripts\run_pptx_check.ps1`
- `scripts\run_real_rehearsal.ps1`

Examples:

```powershell
.\scripts\run_preflight.ps1 -RunId phase11-preflight
.\scripts\run_real_rehearsal.ps1 -RunId phase11-rehearsal -StageRealInputs
.\scripts\run_customer_final.ps1 -RunId phase11-final -CompareToRun phase10-final -StageRealInputs
.\scripts\run_internal_archive.ps1 -RunId phase11-archive -CompareToRun phase10-final
.\scripts\run_pptx_check.ps1 -RunId phase11-pptx -RequirePptx
```

## Recommended Real Rehearsal Procedure

이 절은 승인된 real rehearsal 준비용 참고 문서다. 기본 개발/CI 계약은 위의 fixture/mock 기반 smoke E2E다.

Before real data:
1. Place real Burp, nuclei, and httpx files only in `data\inputs\real\*`.
2. Place override, suppression, and review resolution files in `data\inputs\real\manual` when they are run-specific.
3. Keep sample or fixture files out of the `real` tree.
4. Run preflight and inspect `input_preflight.md`, `input_intake_manifest.json`, and `input_hashes.json`.
5. Run PPTX capability check if the release requires a real presentation file.

Customer final with staged inputs:

```powershell
python -m vuln_pipeline.cli.main `
  --run-id phase11-customer-final `
  --customer-bundle "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml" `
  --auto-select-real-inputs `
  --stage-real-inputs `
  --review-resolution-file "D:\취약점 진단\data\inputs\real\manual\review_resolution.yaml" `
  --compare-to-run phase10-final `
  --package-output `
  --release-candidate `
  --finalize-delivery
```

Bundle plus PPTX requirement:

```powershell
python -m vuln_pipeline.cli.main `
  --run-id phase11-pptx-release `
  --customer-bundle "D:\취약점 진단\app\vuln-pipeline\configs\customer_bundles\default_customer_release.yaml" `
  --auto-select-real-inputs `
  --require-pptx `
  --package-output
```

Archive-only regeneration:

```powershell
python -m vuln_pipeline.cli.main `
  --run-id phase11-archive-only `
  --auto-select-real-inputs `
  --archive-only `
  --compare-to-run phase11-customer-final
```
