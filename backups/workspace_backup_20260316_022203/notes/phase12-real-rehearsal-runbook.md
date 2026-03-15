# Phase12 Real Rehearsal Runbook

## Scope

- 대상 구현체: `D:\취약점 진단\app\vuln-pipeline`
- CLI entrypoint: `python -m vuln_pipeline.cli.main`
- success baseline: `D:\취약점 진단\outputs\runs\phase9-final-demo-v9`
- baseline hard facts:
  - `release_readiness.json.status = ready`
  - `submission_gate.json.status = pass`
  - `final_delivery_manifest.json.final_ready = true`

## Confirmed Current Blockers

현재 readiness checker 기준 blocker는 아래 4개다.

- `override_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `suppression_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `review_resolution_file: manual source is legacy_default; expected real_explicit during real rehearsal`
- `real scan inputs are not ready`

의미:

- live real scan input 3종이 아직 auto-select 조건을 만족하지 않는다.
- live real/manual 3종이 아직 `real_explicit`로 해석되지 않는다.

## Bootstrap First

`notes/phase12-manual-drafts`가 없으면 wrapper는 더 이상 조용히 죽지 않지만, 운영자는 먼저 non-live workspace를 초기화하는 것이 기준이다.

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-templates `
  --run-id "phase12-first-real-run"
```

이 helper는 아래만 만든다.

- `incoming\burp`
- `incoming\nuclei`
- `incoming\httpx`
- `manual-drafts`
- `receipts`
- `artifacts`
- `phase12_workspace_manifest.json`
- `phase12_workspace_manifest.md`

중요:

- bootstrap는 live real dir를 건드리지 않는다.
- incoming workspace는 실제 export를 drop하는 non-live 공간이다.
- live real dir는 readiness/auto-select가 실제로 읽는 운영 경로다.

## Operator Loop

권장 흐름은 아래 순서를 유지한다.

1. `phase12_operator_workspace bootstrap` 또는 wrapper `-InitWorkspace`로 non-live workspace를 먼저 만든다.
2. incoming real scan export를 non-live workspace 아래 `incoming/*`에 놓고 `scan_input_promotion --plan-only`로 inventory/selection/diff/archive 계획까지 확인한다.
3. basename에 excluded keyword가 있거나 ambiguous candidate가 있으면 operator-confirmation-needed 상태로 멈춘다.
4. 필요하면 explicit source, explicit target name, 또는 `--allow-auto-pick` 여부를 결정한다.
5. 명시적으로 `scan_input_promotion --apply --overwrite`를 줘서 live real scan input 3종을 반영한다.
6. `manual-drafts`를 seed하고, 사람이 `draft_candidates`를 검토해 필요한 행만 top-level actionable list로 옮긴다.
7. `manual_promotion --plan-only`로 validation + diff + staged candidate를 본다.
8. 명시적으로 `manual_promotion --apply --overwrite`를 줘서 live real/manual에 반영한다.
9. preflight -> rehearsal -> triage -> comparison 순서로 rerun pack을 확인한다.

live 변경 직전에는 아래 signoff 흐름을 반드시 끼운다.

1. `phase12_signoff_review.json/md`를 생성한다.
2. `phase12_apply_intent.template.json`을 reviewer가 검토하고 수정한다.
3. wrapper에 `-IntentFile`을 주고 apply를 재실행한다.
4. wrapper는 current plan/workspace manifest fingerprint와 intent의 expected fingerprint를 비교한다.
5. stale intent, ambiguous candidate, naming decision required, manual actionable change 미확정, readiness blocker가 남아 있으면 live apply를 막는다.

## Signoff Review

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.phase12_apply_signoff review `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --run-id "phase12-real-iteration" `
  --output-dir "D:\취약점 진단\outputs\runs\phase12-real-iteration\report_data"
```

출력:

- `phase12_signoff_review.json`
- `phase12_signoff_review.md`
- `phase12_apply_intent.template.json`

review pack은 hard fact와 suggestion을 분리해서 아래를 모아준다.

- workspace root / incoming root / working dir / live dir
- scan plan / manual plan 존재 여부
- ambiguous candidate 여부
- naming decision required 여부
- manual actionable change 여부
- readiness blocker 잔존 여부
- missing prerequisite 목록
- exact next command

상태 의미:

- `not_ready_for_apply`
  - apply blocker가 남아 있음
- `review_required`
  - blocker는 없지만 reviewer signoff가 아직 필요함
- `ready_for_apply_consideration`
  - 자동 승인 아님
  - 현재 fact 기준으로 intent 검증까지 통과하면 apply를 검토할 수 있음

## Intent File

template 기본값은 apply 관련 필드가 모두 `false`다.

- `apply_scan_promotion`
- `apply_manual_promotion`
- `reviewed_by`
- `reviewed_at`
- `notes`
- `expected_*_hash`
- `unresolved_items`
- `acknowledgements.*`

중요:

- template를 그대로 쓰지 말고 reviewer가 편집한 복사본을 `-IntentFile`로 넘긴다.
- plan hash/fingerprint 검증은 review 이후 artifact가 바뀌었는데 이전 signoff를 재사용하는 stale apply를 막기 위해 필요하다.
- signoff review를 다시 만들면 intent도 다시 검토해야 한다.

## Working Draft And Actionable List

중요한 구분:

- `draft_candidates`
  - operator 참고용 후보 목록
  - 자동 승인되지 않는다
  - promotion helper가 live로 반영하지 않는다
- top-level actionable list
  - `overrides`
  - `suppressions`
  - `review_resolutions`
  - promotion helper가 실제 staged/live payload로 읽는 유일한 영역

`manual_bootstrap` 또는 workspace bootstrap seed는 safe default만 만든다.

- `override_working.yaml`
- `suppression_working.yaml`
- `review_resolution_working.yaml`
- `bootstrap_worklist.md`

이때 actionable list는 비어 있고 `draft_candidates`만 채워질 수 있다.

## Scan Promotion Helper

plan-only:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.scan_input_promotion `
  --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --output-dir "D:\취약점 진단\outputs\runs\phase12-iteration\report_data\scan_promotion" `
  --plan-only
```

apply:

```powershell
python -m vuln_pipeline.cli.scan_input_promotion `
  --incoming-root "D:\취약점 진단\notes\phase12-operator-workspace\incoming" `
  --live-root "D:\취약점 진단\data\inputs\real" `
  --output-dir "D:\취약점 진단\outputs\runs\phase12-iteration\report_data\scan_promotion" `
  --apply `
  --overwrite
```

plan mode 산출물:

- `scan_input_promotion_plan.json`
- `scan_input_promotion_plan.md`
- `live_scan_inventory.json`
- `live_scan_inventory.md`

apply mode 추가 산출물:

- `scan_input_promotion_receipt.json`
- `scan_input_promotion_receipt.md`
- timestamped archive 경로

해석 포인트:

- ambiguous incoming candidate
  - 기본은 block
  - explicit source가 있으면 그 파일을 우선
  - `--allow-auto-pick`가 있을 때만 현재 auto-select 규칙으로 최신 1개를 고른다
- excluded keyword basename
  - live에 그대로 두면 auto-select 대상이 되지 않는다
  - helper는 조용히 rename 하지 않는다
  - `naming decision required`로 남기고, 명시적 target name이 있을 때만 반영 가능하다
- live inventory
  - hard fact: active file, eligible file count, invalid/excluded file 목록
  - inference: 운영 목표인 tool별 valid active file 1개 유지 여부

## Manual Promotion Helper

template seed 또는 previous run seed가 필요하면:

```powershell
python -m vuln_pipeline.cli.phase12_operator_workspace bootstrap `
  --workspace-root "D:\취약점 진단\notes\phase12-operator-workspace" `
  --seed-from-run-root "D:\취약점 진단\outputs\runs\phase12-real-rehearsal" `
  --run-id "phase12-real-iteration"
```

plan-only:

```powershell
Set-Location "D:\취약점 진단\app\vuln-pipeline"
python -m vuln_pipeline.cli.manual_promotion `
  --working-dir "D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts" `
  --output-dir "D:\취약점 진단\outputs\runs\phase12-iteration\report_data\manual_promotion" `
  --plan-only
```

apply:

```powershell
python -m vuln_pipeline.cli.manual_promotion `
  --working-dir "D:\취약점 진단\notes\phase12-operator-workspace\manual-drafts" `
  --live-manual-dir "D:\취약점 진단\data\inputs\real\manual" `
  --output-dir "D:\취약점 진단\outputs\runs\phase12-iteration\report_data\manual_promotion" `
  --apply `
  --overwrite
```

plan mode 산출물:

- `manual_promotion_plan.json`
- `manual_promotion_plan.md`
- `*_candidate.yaml` 3종
- existing live 대비 diff summary

apply 전 확인 포인트:

- blocker가 없는지
- staged candidate validation이 `format_valid=true`인지
- existing live file에 unexpected key/structure 경고가 없는지
- actionable list가 실제로 채워졌는지

apply 후 확인 포인트:

- backup 생성 여부
- `manual_promotion_receipt.json`
- `manual_promotion_receipt.md`
- before/after hash, entry count delta

## Preflight And Rehearsal

preflight:

```powershell
.\scripts\run_preflight.ps1 -RunId phase12-real-preflight -StageRealInputs
```

rehearsal:

```powershell
.\scripts\run_real_rehearsal.ps1 -RunId phase12-real-rehearsal -StageRealInputs
```

blocked 상태여도 아래 triage pack은 남는다.

- `post_run_triage.json`
- `post_run_triage.md`
- `post_run_triage_worklist.csv`
- `manual_validation.json`
- `manual_validation.md`

## Iteration Wrapper

한 번에 promotion + preflight + rehearsal + triage + comparison까지 이어서 보려면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId phase12-real-iteration `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -PreviousRunId phase12-real-rehearsal
```

기본은 scan/manual promotion 모두 `plan-only`다. 실제 live 반영은 명시적으로 `-ApplyScanPromotion -ApplyPromotion -Overwrite`를 줘야 한다.

signoff review까지만 만들고 멈추려면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId phase12-real-iteration `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -PreviousRunId phase12-real-rehearsal `
  -GenerateSignoffReview `
  -StopAfterSignoffReview
```

intent를 포함한 apply:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId phase12-real-iteration `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -PreviousRunId phase12-real-rehearsal `
  -IntentFile "D:\취약점 진단\outputs\runs\phase12-real-iteration\report_data\phase12_apply_intent.json" `
  -ApplyScanPromotion `
  -ApplyPromotion `
  -Overwrite
```

workspace가 아직 없으면:

```powershell
.\scripts\run_phase12_iteration.ps1 `
  -RunId phase12-real-iteration `
  -WorkspaceRoot "D:\취약점 진단\notes\phase12-operator-workspace" `
  -InitWorkspace `
  -SeedManualDraftsFromTemplates `
  -StopAfterBootstrap
```

wrapper 보강 사항:

- `-WorkspaceRoot`를 주면 `incoming`과 `manual-drafts` 기본값을 안전하게 유도한다.
- `-InitWorkspace`가 있으면 bootstrap helper를 먼저 호출한다.
- working dir가 없고 `-InitWorkspace`가 없으면 manual promotion은 stub plan으로 남기고, `phase12_operator_case.json/md`에 exact next command를 적는다.
- apply 플래그가 있으면 wrapper는 먼저 current plan/signoff review를 만들고, 유효한 intent가 없으면 live 변경을 수행하지 않는다.
- intent fingerprint가 현재 signoff review와 다르면 stale intent로 간주해 block 한다.
- blocked/fail 상태여도 triage/comparison/operator case artifact는 계속 남긴다.
- blocked/fail/pass 모두에서 `phase12_evidence_pack.json/md`를 남긴다.

wrapper가 출력하는 핵심 경로:

- `phase12_operator_case.json`
- `phase12_operator_case.md`
- `phase12_signoff_review.json`
- `phase12_signoff_review.md`
- `phase12_apply_intent.template.json`
- `phase12_apply_intent_validation.json`
- `phase12_apply_intent_validation.md`
- `phase12_evidence_pack.json`
- `phase12_evidence_pack.md`
- `phase12_workspace_manifest.json`
- `phase12_workspace_manifest.md`
- scan promotion plan/receipt
- promotion plan/receipt
- `input_preflight.json`
- `real_input_selection.json`
- `post_run_triage.md/json/csv`
- `manual_validation.md/json`
- `rerun_comparison.md/json`
- `release_readiness.json`
- `submission_gate.json`
- `final_delivery_manifest.json`
- `review_closure_status.json`
- customer/internal zip

blocked 상태여도 아래는 남긴다.

- operator case
- signoff review
- scan promotion plan/live inventory
- manual promotion plan
- triage pack
- comparison pack
- evidence pack

## Operator Case Manifest

`phase12_operator_case.json/md`는 hard fact와 suggestion을 분리해서 보여준다.

- hard fact
  - workspace root / working dir / incoming root / live dir
  - previous run root
  - customer bundle / branding / readiness path 존재 여부
  - live scan inventory 상태
  - apply flag 사용 여부
  - 각 artifact path 존재 여부와 status
  - blocked reason 요약
- suggestion
  - operator-confirmation-needed
  - exact next commands

이 파일은 run 시작 직전과 종료 후에 다시 써진다.

## Comparison Summary

comparison helper:

```powershell
python -m vuln_pipeline.cli.rerun_comparison `
  --current-run-root "D:\취약점 진단\outputs\runs\phase12-real-rerun" `
  --previous-run-root "D:\취약점 진단\outputs\runs\phase12-real-rehearsal"
```

출력:

- `rerun_comparison.json`
- `rerun_comparison.md`

최소 비교 항목:

- blocked/pass/ready/final_ready 변화
- blocker 수 변화
- missing artifact 수 변화
- unresolved review item 변화
- customer/internal zip 존재 변화
- live manual 상태 변화

해석 규칙:

- hard fact:
  - status 값
  - count delta
  - artifact 존재 여부 변화
- inference:
  - `improved`, `regressed`, `no_material_change`
  - hard fact delta를 요약한 운영 보조 판단일 뿐 자동 승인 아니다

## Evidence Pack

evidence pack은 blocked/fail/pass 모두에서 reviewer가 한 번에 보는 post-run 묶음이다.

포함 항목:

- run id / run root / previous run root
- workspace root / incoming root / working dir / live dir
- apply flag 사용 여부
- intent file 존재/검증 상태
- scan/manual promotion receipt 경로
- input_preflight / real_input_selection
- post_run_triage / manual_validation / rerun_comparison
- release_readiness / submission_gate / final_delivery_manifest / review_closure_status
- customer/internal zip
- blocked reason / missing artifact / next command

읽는 법:

- hard fact 섹션에서 현재 run rollup, artifact 존재, blocked reason을 본다.
- suggestion 섹션은 operator next step만 제공하며 자동 승인 의미가 아니다.

## Status Interpretation

- `blocked`
  - readiness 또는 preflight에서 멈춤
  - downstream artifact 일부가 비어 있을 수 있다
- `fail`
  - pipeline은 돌았지만 readiness/submission/final gate에서 막힘
- `ready`
  - release readiness는 준비됐지만 최종 pass와 동일하지 않다
- `pass`
  - submission gate 통과
- `final_ready=true`
  - final manifest 기준 최종 패키징 준비 완료

## Success Check

최종적으로 아래가 다시 만족되어야 한다.

- `release_readiness.json.status = ready`
- `submission_gate.json.status = pass`
- `final_delivery_manifest.json.final_ready = true`
- `review_closure_status.json.unresolved_review_items = 0`
- `customer_submission_*.zip` 존재
- `internal_archive_*.zip` 존재
