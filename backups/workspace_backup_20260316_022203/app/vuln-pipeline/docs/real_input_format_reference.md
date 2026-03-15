# Real Input Format Reference

이 문서는 `app/vuln-pipeline/src/vuln_pipeline` 현재 코드 기준만 정리한다.

## Non-Live Workspace First

first real run 전에는 live real dir 대신 non-live operator workspace를 먼저 만든다.

```powershell
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-templates `
  --run-id "phase12-first-real-run"
```

bootstrap 결과:

- `incoming\burp`
- `incoming\nuclei`
- `incoming\httpx`
- `manual-drafts`
- `receipts`
- `artifacts`
- `phase12_workspace_manifest.json`
- `phase12_workspace_manifest.md`

중요:

- incoming workspace는 실제 export drop과 plan/apply 검토를 위한 non-live 공간이다.
- `data\inputs\real\*`는 readiness와 auto-select가 실제로 읽는 live 경로다.
- live dir와 non-live workspace를 혼동하면 excluded/sample/template 파일이 readiness blocker를 유발할 수 있다.

## Auto-Select Rules

scan auto-select 규칙은 그대로 유지된다.

- Burp: `.xml` + `256` bytes 이상
- nuclei: `.json` 또는 `.jsonl` + `128` bytes 이상
- httpx: `.jsonl` + `128` bytes 이상
- 제외 키워드: `sample`, `fixture`, `test`, `realish`
- tool별 최신 eligible 1개 선택

이 규칙은 scan promotion helper와 readiness checker에서도 같은 hard fact로 재사용된다.

live real intake 루트:

- `data\inputs\real\burp`
- `data\inputs\real\nuclei`
- `data\inputs\real\httpx`
- `data\inputs\real\manual`

권장 non-live drop 루트:

- `notes\phase12-operator-workspace\incoming\burp`
- `notes\phase12-operator-workspace\incoming\nuclei`
- `notes\phase12-operator-workspace\incoming\httpx`

## Manual Live Files

manual support 3종:

- `override_file`
- `suppression_file`
- `review_resolution_file`

공통 규칙:

- 확장자: `.yaml`, `.yml`, `.json`
- live 경로: `data\inputs\real\manual`
- `sample`, `fixture`, `test`, `realish`가 파일명에 있으면 제외
- group별 최신 eligible 1개만 선택
- real rehearsal readiness에서는 `manual_source=real_explicit`이어야 한다

### override_file

- 파일명 패턴: `override`
- 허용 payload:
  - `{overrides: [...]}`
  - top-level list
- actionable row 식별자:
  - `issue_id` 또는 `finding_id`

### suppression_file

- 파일명 패턴: `suppression` 또는 `suppress`
- 허용 payload:
  - `{suppressions: [...]}`
  - top-level list
- actionable row 매칭 필드:
  - `cluster_key`
  - `host`
  - `path_pattern`
  - `weakness_family`
  - `primary_cwe`
  - `title_regex`

### review_resolution_file

- 파일명 패턴: `review_resolution`, `resolution`, `closeout`
- 허용 payload:
  - `{review_resolutions: [...]}`
  - top-level list
- actionable row 식별자:
  - `issue_id`

## Working Draft Format

working draft는 live file이 아니다.

- `override_working.yaml`
- `suppression_working.yaml`
- `review_resolution_working.yaml`

권장 non-live 위치:

- `notes\phase12-operator-workspace\manual-drafts`

working draft 공통 구조:

```yaml
overrides: []
draft_candidates: []
notes: []
bootstrap_metadata: {}
```

또는 suppression/review_resolution에 맞는 top-level key를 사용한다.

중요:

- `draft_candidates`
  - 참고용 후보
  - 자동 승인 금지
  - promotion helper가 live 대상에 포함하지 않음
- top-level actionable list
  - `overrides`
  - `suppressions`
  - `review_resolutions`
  - 사람이 채워야 하는 실제 promotion 대상

## Promotion Helper

scan promotion은 working draft가 아니라 real scan export landing 용도다.

```powershell
python -m vuln_pipeline.cli.scan_input_promotion `
  --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data\scan_promotion" `
  --plan-only
```

scan promotion plan 산출물:

- `scan_input_promotion_plan.json`
- `scan_input_promotion_plan.md`
- `live_scan_inventory.json`
- `live_scan_inventory.md`

scan promotion apply 추가 산출물:

- `scan_input_promotion_receipt.json`
- `scan_input_promotion_receipt.md`
- timestamped archive 경로

scan promotion guardrail:

- 기본은 `plan-only`
- `apply`는 `--overwrite`가 있어야 live 변경을 허용
- ambiguous incoming candidate는 기본 block
- explicit source 또는 `--allow-auto-pick`가 있을 때만 선택 진행
- excluded keyword basename은 그대로 live 반영하면 auto-select에서 제외되므로 `naming decision required`
- helper는 조용히 rename 하지 않으며, 명시적 target name이 있을 때만 안전하게 반영
- 운영 목표는 live에 tool별 valid active file 1개 유지다

`manual_promotion`은 working draft에서 top-level actionable list만 읽는다.

working dir가 없으면 먼저 bootstrap 또는 `manual_bootstrap`로 seed한다.

plan-only:

```powershell
python -m vuln_pipeline.cli.manual_promotion `
  --working-dir "D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data\manual_promotion" `
  --plan-only
```

apply:

```powershell
python -m vuln_pipeline.cli.manual_promotion `
  --working-dir "D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts" `
  --live-manual-dir "D:\취약점 진단\data\inputs\real\manual" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data\manual_promotion" `
  --apply `
  --overwrite
```

plan mode 산출물:

- `manual_promotion_plan.json`
- `manual_promotion_plan.md`
- `*_candidate.yaml`

apply mode 추가 산출물:

- `manual_promotion_receipt.json`
- `manual_promotion_receipt.md`
- backup 파일

guardrail:

- plan-only는 live 파일을 수정하지 않는다
- apply는 validation + diff + backup 후에만 진행된다
- existing live file에 unexpected key/structure가 있으면 block 또는 강한 경고를 남긴다
- actionable list가 비어 있고 draft_candidates만 있으면 `human_selection_required` 상태가 될 수 있다

## Signoff And Intent Gate

apply 직전에는 signoff review를 만든다.

```powershell
python -m vuln_pipeline.cli.phase12_apply_signoff review `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --run-id "<run-id>" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data"
```

출력:

- `phase12_signoff_review.json`
- `phase12_signoff_review.md`
- `phase12_apply_intent.template.json`

signoff review는 hard fact와 suggestion을 분리해서 보여준다.

- hard fact
  - workspace/incoming/working/live path
  - plan 존재 여부
  - ambiguous candidate / naming decision required / manual actionable change / readiness blocker 여부
  - missing prerequisite
- suggestion
  - 현재 상태 기준 exact next command

intent gate 원칙:

- 기본은 review-first / signoff-first
- live scan/manual apply는 명시적 apply flag와 유효한 intent가 둘 다 있을 때만 허용
- wrapper는 current signoff review의 fingerprint와 intent의 `expected_*_hash`를 비교한다
- fingerprint mismatch는 stale intent이므로 block 된다
- ambiguous incoming source 자동 확정 금지
- draft_candidates 자동 승인 금지

대표적인 apply block 시나리오:

- intent 없음
- stale intent
- ambiguous candidate 잔존
- naming decision required 잔존
- manual actionable change 미확정

## Validation And Comparison

wrapper로 bootstrap -> plan -> apply -> preflight -> rehearsal -> triage -> comparison을 묶으려면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId "<run-id>" `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -PreviousRunId "phase12-real-rehearsal"
```

workspace가 없으면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId "<run-id>" `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -InitWorkspace `
  -SeedManualDraftsFromTemplates `
  -StopAfterBootstrap
```

wrapper는 `phase12_operator_case.json/md`를 pre/post 시점에 남긴다. 이 파일에서 hard fact와 next command를 같이 읽는다.

signoff review까지만 만들고 멈추려면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId "<run-id>" `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -GenerateSignoffReview `
  -StopAfterSignoffReview
```

intent를 포함한 apply:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId "<run-id>" `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -IntentFile "D:\취약점 진단\outputs\runs\<run-id>\report_data\phase12_apply_intent.json" `
  -ApplyScanPromotion `
  -ApplyPromotion `
  -Overwrite
```

rerun 전에는 아래 두 helper를 함께 보는 것이 기준이다.

```powershell
python -m vuln_pipeline.cli.post_run_triage --run-root "D:\취약점 진단\outputs\runs\<run-id>"
python -m vuln_pipeline.cli.rerun_comparison `
  --current-run-root "D:\취약점 진단\outputs\runs\<current-run>" `
  --previous-run-root "D:\취약점 진단\outputs\runs\<previous-run>"
```

핵심 출력:

- `post_run_triage.json`
- `manual_validation.json`
- `rerun_comparison.json`

해석:

- hard fact
  - blocked/pass/ready/final_ready
  - blocker/missing artifact/review item count
  - zip 존재 여부
  - `live_scan_inventory`의 active file / eligible count / invalid-or-excluded file 상태
- inference
  - `improved`, `regressed`, `no_material_change`
  - hard fact delta 기반 운영 요약일 뿐 자동 승인 아님

## Evidence Pack

wrapper는 blocked/fail/pass와 관계없이 `phase12_evidence_pack.json/md`를 남긴다.

포함 항목:

- run id / run root / previous run root
- workspace root / incoming root / working dir / live dir
- apply flag 사용 여부
- intent file 존재/검증 상태
- scan/manual promotion receipt
- `input_preflight.json`
- `real_input_selection.json`
- `post_run_triage.*`
- `manual_validation.*`
- `rerun_comparison.*`
- `release_readiness.json`
- `submission_gate.json`
- `final_delivery_manifest.json`
- `review_closure_status.json`
- customer/internal zip
- blocked reason / missing artifact / next command

live dir와 non-live workspace를 혼동하면 안 되는 이유:

- live dir는 readiness와 auto-select가 실제로 읽는 운영 입력이다
- non-live workspace는 계획과 reviewer signoff를 위한 안전한 검토 공간이다
- 두 공간이 섞이면 template/sample/미검토 초안이 실운영 입력으로 해석될 수 있다

## Safe Templates

safe template 위치:

- `app\vuln-pipeline\docs\examples\real_manual_templates\override_template.yaml`
- `app\vuln-pipeline\docs\examples\real_manual_templates\suppression_template.yaml`
- `app\vuln-pipeline\docs\examples\real_manual_templates\review_resolution_template.yaml`

주의:

- template와 working draft를 `data\inputs\real\manual`에 그대로 두지 않는다
- live input과 non-live 초안은 항상 분리한다
