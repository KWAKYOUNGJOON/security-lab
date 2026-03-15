# Real Inputs Intake Checklist

## Workspace Bootstrap

first real run 전에는 live dir 대신 non-live operator workspace를 먼저 만든다.

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-templates `
  --run-id "phase12-first-real-run"
```

필수 확인:

- [ ] `notes\phase12-operator-workspace\incoming\burp`
- [ ] `notes\phase12-operator-workspace\incoming\nuclei`
- [ ] `notes\phase12-operator-workspace\incoming\httpx`
- [ ] `notes\phase12-operator-workspace\manual-drafts`
- [ ] `phase12_workspace_manifest.json`
- [ ] `phase12_workspace_manifest.md`
- [ ] bootstrap는 `data\inputs\real\*` live dir를 수정하지 않았는지 확인

## First Check

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
.\scripts\check_real_input_readiness.ps1
```

현재 저장소 기준 blocker:

- `override_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `suppression_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `review_resolution_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `real scan inputs are not ready`

## Recommended Directory Layout

- non-live workspace
  - `notes\phase12-operator-workspace\incoming\burp`
  - `notes\phase12-operator-workspace\incoming\nuclei`
  - `notes\phase12-operator-workspace\incoming\httpx`
  - `notes\phase12-operator-workspace\manual-drafts`
- live real dirs
  - `data\inputs\real\burp`
  - `data\inputs\real\nuclei`
  - `data\inputs\real\httpx`
  - `data\inputs\real\manual`

중요:

- incoming workspace는 실제 export를 임시 drop하고 plan/apply를 검토하는 non-live 공간이다.
- live real dir는 auto-select/readiness가 실제로 읽는 운영 입력이다.
- 두 공간을 혼동하면 template/sample 또는 미검토 초안이 readiness에 끼어들 수 있으므로 분리 유지가 필수다.

## Scan Input Checklist

scan landing/promotion plan-only:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.scan_input_promotion `
  --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data\scan_promotion" `
  --plan-only
```

scan landing/promotion apply:

```powershell
python -m vuln_pipeline.cli.scan_input_promotion `
  --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data\scan_promotion" `
  --apply `
  --overwrite
```

- [ ] `data\inputs\real\burp`에 `.xml`, 256 bytes 이상, 제외 키워드 없는 실제 Burp export
- [ ] `data\inputs\real\nuclei`에 `.json` 또는 `.jsonl`, 128 bytes 이상, 제외 키워드 없는 실제 nuclei export
- [ ] `data\inputs\real\httpx`에 `.jsonl`, 128 bytes 이상, 제외 키워드 없는 실제 httpx export
- [ ] tool별 최신 1개가 실제로 선택되는지 `real_input_readiness.json` 또는 `real_input_selection.json`으로 확인
- [ ] `scan_input_promotion_plan.json`에서 tool별 `selected / rejected / ambiguous` 후보를 확인
- [ ] basename에 `sample|fixture|test|realish`가 들어가면 `naming decision required`로 처리되는지 확인
- [ ] ambiguous candidate가 있으면 기본은 block 되며, explicit source 또는 `--allow-auto-pick` 없이는 진행하지 않음
- [ ] live real 디렉터리에 sample/template/fixture/test 파일을 두지 않음
- [ ] live에는 tool별 valid active file 1개만 남기는 것이 운영 목표임을 확인
- [ ] extra live file은 삭제 대신 archive/receipt로 추적되게 계획되었는지 확인

## Manual Input Checklist

- [ ] `data\inputs\real\manual` 아래 override live 파일 준비
- [ ] `data\inputs\real\manual` 아래 suppression live 파일 준비
- [ ] `data\inputs\real\manual` 아래 review resolution live 파일 준비
- [ ] 세 파일 모두 `manual_source=real_explicit`로 해석되는지 확인
- [ ] 세 파일 모두 parse/top-level/reference 기준 구조적으로 유효한지 `manual_validation.md`로 확인

## Working Draft Checklist

`notes\phase12-manual-drafts`가 없거나 비어 있으면 bootstrap로 non-live workspace를 먼저 초기화한다.

template seed:

```powershell
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-templates `
  --run-id "<run-id>"
```

run-root seed:

```powershell
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-run-root "D:\취약점 진단\outputs\runs\<previous-run-id>" `
  --run-id "<run-id>"
```

확인 포인트:

- [ ] `notes\phase12-operator-workspace\manual-drafts\override_working.yaml`의 `overrides`를 사람이 채웠는지
- [ ] `notes\phase12-operator-workspace\manual-drafts\suppression_working.yaml`의 `suppressions`를 사람이 채웠는지
- [ ] `notes\phase12-operator-workspace\manual-drafts\review_resolution_working.yaml`의 `review_resolutions`를 사람이 채웠는지
- [ ] `draft_candidates`는 참고만 하고 자동 승인하지 않았는지
- [ ] `bootstrap_worklist.md`에서 추천 working file과 actionable list를 확인했는지
- [ ] `phase12_workspace_manifest.md`의 `operator-confirmation-needed`와 `recommended_next_commands`를 읽었는지

정의:

- `draft_candidates`
  - 참고용 후보
  - promotion helper가 live 반영 대상으로 보지 않음
- top-level actionable list
  - live candidate와 live file에 실제 반영되는 영역

## Promotion Checklist

역할 구분:

- `scan_input_promotion`
  - incoming real export landing, live scan input inventory, archive/receipt 관리
- `manual_promotion`
  - reviewed working draft를 live real/manual 3종으로 반영

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

apply 전:

- [ ] `manual_promotion_plan.json.status`가 `blocked`가 아님
- [ ] `manual_promotion_plan.md`에서 diff summary 확인
- [ ] existing live file unexpected structure 경고가 없음
- [ ] staged candidate validation이 통과함
- [ ] empty actionable list인데 draft_candidates만 있는 상태인지 확인

apply 후:

- [ ] backup 생성 확인
- [ ] receipt 생성 확인
- [ ] before/after hash와 entry count delta 확인

scan apply 후:

- [ ] `scan_input_promotion_receipt.json` 생성 확인
- [ ] `live_scan_inventory.json`에서 tool별 `active_file`이 1개인지 확인
- [ ] archive 경로가 timestamped path인지 확인
- [ ] selection reason, source size/mtime, before/after hash가 receipt에 남았는지 확인

## Signoff Checklist

signoff review 생성:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_apply_signoff review `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --run-id "<run-id>" `
  --output-dir "D:\취약점 진단\outputs\runs\<run-id>\report_data"
```

- [ ] `phase12_signoff_review.json/md` 생성 확인
- [ ] hard fact와 suggestion이 분리되어 있는지 확인
- [ ] `phase12_apply_intent.template.json` 생성 확인
- [ ] reviewer가 `reviewed_by`, `reviewed_at`, `acknowledgements.*`, apply flags를 직접 채웠는지 확인
- [ ] `expected_*_hash`가 current plan/workspace manifest 기준인지 확인
- [ ] ambiguous candidate 잔존 여부 확인
- [ ] naming decision required 잔존 여부 확인
- [ ] manual actionable change 미확정 상태인지 확인
- [ ] readiness blocker가 남아 있지 않은지 확인

apply block 대표 시나리오:

- [ ] intent file 없음
- [ ] stale intent
- [ ] ambiguous candidate 잔존
- [ ] naming decision required 잔존
- [ ] manual actionable change 미확정

## Rerun Checklist

1. `phase12_operator_workspace bootstrap`
2. non-live incoming workspace에 실제 export 3종 drop
3. `scan_input_promotion --plan-only`
4. 필요 시 `scan_input_promotion --apply --overwrite`
5. `manual_promotion --plan-only`
6. 필요 시 `manual_promotion --apply --overwrite`
7. `run_preflight.ps1 -RunId <id> -StageRealInputs`
8. `run_real_rehearsal.ps1 -RunId <id> -StageRealInputs`
9. `phase12_signoff_review.md/json` 확인
10. reviewer가 intent를 편집하고 `run_phase12_iteration.ps1 -IntentFile ... -ApplyScanPromotion -ApplyPromotion` 실행
11. `phase12_operator_case.md/json` 확인
12. `post_run_triage.md/json/csv`, `manual_validation.md/json`, `rerun_comparison.md/json`, `phase12_evidence_pack.md/json` 확인

comparison 해석:

- `improved`
  - hard fact delta 기준 운영상 개선 신호
- `regressed`
  - blocker, missing artifact, unresolved review item이 악화
- `no_material_change`
  - high-signal delta가 없음

이 값은 자동 승인이나 취약점 확정이 아니다.

evidence pack 확인 포인트:

- hard fact로 blocked reason / missing artifact / intent validation 상태를 먼저 본다.
- suggestion은 다음 실행 명령 안내일 뿐 자동 승인 의미가 아니다.

## Final Real Gate Checklist

signoff / intent / apply / reconciliation 뒤에도 final real gate를 한 번 더 본다. 이유는 current live 상태가 실제 rehearsal 직전 기준으로 다시 수렴했는지 fresh preflight 기준으로 확인해야 하기 때문이다.

gate 생성:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_real_gate `
  --run-root "D:\취약점 진단\outputs\runs\<run-id>" `
  --workspace-root "D:\취약점 진단" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --refresh-preflight `
  --strict
```

wrapper 기본 흐름:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId "<run-id>" `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -GenerateRealGate `
  -RequireRealGateForRehearsal `
  -RefreshPreflightBeforeGate
```

gate가 확인하는 항목:

- [ ] current live active file 3종이 tool별 exactly 1개인지
- [ ] current live active basename에 `sample|fixture|test|realish`가 없는지
- [ ] current live active 와 fresh preflight selected 가 일치하는지
- [ ] current live active 와 `real_input_selection` selected 가 일치하는지
- [ ] promotion receipt target/hash 와 current live path/hash 가 일치하는지
- [ ] manual 3종 live file 이 실제 존재하는지
- [ ] manual 3종이 `legacy_default`가 아니고 가능하면 hard fact로 `real_explicit`인지
- [ ] `input_preflight.status=ready`, blocker 0, `manual_sources_ready=true` 인지
- [ ] `phase12_apply_intent_validation` 이 `valid/pass` 인지
- [ ] apply receipt, archive, backup 이 실제 존재하는지

blocked 대표 시나리오:

- [ ] `real scan inputs are not ready`
- [ ] manual source 가 아직 `legacy_default`
- [ ] current live 와 preflight selected 가 mismatch
- [ ] stale preflight 또는 fresh preflight 미생성
- [ ] intent 는 valid 이지만 current live / receipt 가 아직 converged 하지 않음

표준 순서:

1. signoff review / intent validation 확인
2. scan/manual apply receipt 확인
3. `phase12_apply_reconciliation.json/md` 확인
4. `phase12_real_gate.json/md` 생성
5. gate가 `ready_for_rehearsal` 또는 `ready_for_rehearsal_with_warnings` 인지 확인
6. 그다음 rehearsal 실행
7. blocked 면 rehearsal 로 넘어가지 말고 `missing_input_fix_command` 또는 `rollback_plan_command` 로 되돌아간다

UTF-8 주의:

- PowerShell wrapper는 UTF-8 console encoding을 먼저 설정한다.
- Python subprocess test는 `encoding=\"utf-8\", errors=\"replace\"` 로 실행해 cp949 decode warning을 줄인다.

## Post-Apply Reconciliation Checklist

apply 뒤에는 아래 순서를 기준으로 본다.

1. `phase12_signoff_review.json/md`
2. `phase12_apply_intent_validation.json/md`
3. `scan_input_promotion_receipt.json/md`
4. `manual_promotion_receipt.json/md`
5. `phase12_apply_reconciliation.json/md`
6. `phase12_evidence_pack.json/md`
7. 필요 시 `phase12_rollback_plan.json/md`

reconciliation 생성:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_apply_reconciliation `
  --run-root "D:\취약점 진단\outputs\runs\<run-id>" `
  --workspace-root "D:\취약점 진단" `
  --live-root "D:\취약점 진단\data\inputs\real"
```

- [ ] apply 자체가 receipt 기준으로 실제 수행되었는지 확인
- [ ] planned target vs current live active file 이 일치하는지 확인
- [ ] current live active file vs preflight selected file 이 일치하는지 확인
- [ ] manual live file path/hash 가 receipt after_hash 와 일치하는지 확인
- [ ] scan archive / manual backup 경로가 실제 존재하는지 확인
- [ ] readiness blocker 가 여전히 남는지 확인
- [ ] hard fact 와 inference/suggestion 을 구분해서 읽었는지 확인

rollup 해석:

- `no_apply_detected`
  - apply receipt 부재
- `reconciled`
  - receipt, current live, selection이 hard fact 기준 정합
- `reconciled_with_warnings`
  - 정합은 대체로 맞지만 follow-up warning 잔존
- `reconciliation_failed`
  - live mismatch, missing archive/backup, stale artifact gap 등 확인 필요

## Rollback Checklist

rollback 기본은 plan-only 다.

plan:

```powershell
python -m vuln_pipeline.cli.phase12_rollback `
  --run-root "D:\취약점 진단\outputs\runs\<run-id>" `
  --workspace-root "D:\취약점 진단" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --plan-only
```

apply:

```powershell
python -m vuln_pipeline.cli.phase12_rollback `
  --run-root "D:\취약점 진단\outputs\runs\<run-id>" `
  --workspace-root "D:\취약점 진단" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --apply `
  --overwrite
```

또는 wrapper:

```powershell
.\scripts\run_phase12_rollback.ps1 -RunRoot "D:\취약점 진단\outputs\runs\<run-id>"
```

- [ ] `phase12_rollback_plan.json/md` 에 restore 대상, overwrite 대상, missing backup/archive 가 정리됐는지 확인
- [ ] restore source 가 없으면 자동 delete/empty 를 하지 않고 block 되는지 확인
- [ ] apply 시 current live 재백업이 생성되는지 확인
- [ ] `phase12_rollback_receipt.json/md` 에 restored target, source backup/archive, before/after hash, restore timestamp 가 남는지 확인

rollback 검토 트리거:

- [ ] preflight/rehearsal 이 apply 직후 blocked/fail 로 바뀜
- [ ] wrong file promoted 또는 target naming 오적용
- [ ] stale intent 기반 apply 가 뒤늦게 발견됨
- [ ] reconciliation 에서 planned target/current live mismatch 가 발견됨
