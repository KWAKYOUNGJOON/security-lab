# 취약점 자동 분석 + 보고서 생성 프로젝트 작업 루트

현재 이 저장소의 메인 구현체와 재현 기준은 `app/vuln-pipeline`이다.

승인된 실데이터 연결 전까지는 fixture/mock 기반 보고서 자동화 E2E를 우선하며, 실제 진단 준비나 실데이터 수집은 기본 작업 범위에 포함하지 않는다.

## 현재 우선 경로

- `app/vuln-pipeline`: 현행 구현체, 테스트, fixture 기반 E2E, 샘플 산출물 중심
- `app/reporting/reporting_starter_v3_package`: legacy/reference 성격의 이전 보고서 패키지

## 폴더 구조

- `app/scanner/hexstrike-ai`: 스캐너 또는 분석 엔진 원본 코드
- `app/reporting/reporting_starter_v3_package`: legacy/reference 보고서 생성 패키지 원본 코드
- `scripts/run`, `scripts/setup`, `scripts/utils`: 실행, 환경 준비, 유틸 스크립트 분류용 폴더
- `data/fixtures/real_fixtures`: 실제 또는 정제된 테스트 입력
- `data/schemas`, `data/samples`: 스키마와 샘플 데이터
- `outputs/runs`, `outputs/temp`: 실행 결과와 임시 산출물
- `reports/templates`, `reports/drafts`, `reports/final`, `reports/evidence`: 보고서 템플릿, 초안, 최종본, 증적 관리
- `notes/handoff`, `notes/troubleshooting`, `notes/decisions`, `notes/private`: 인수인계, 문제 해결, 의사결정, 민감 메모
- `reference/standards`, `reference/burp`, `reference/training`: 원본 참고자료 보관
- `knowledge/summaries`, `knowledge/checklists`, `knowledge/mappings`, `knowledge/prompts`: 재가공된 지식 자산

## Git 추적 원칙

Git에는 코드, 설정, 문서, 스키마, 재가공 지식, 비민감 샘플을 추적한다.

다음 항목은 기본적으로 제외한다.

- `outputs/`
- `reports/final/`
- `reports/evidence/`
- `notes/private/`
- `reference/`
- 캐시, 로그, 임시 파일, 대용량 문서 산출물

## Reference와 Knowledge의 구분

`reference`는 원본 자료를 보관하는 영역이다.

`knowledge`는 원본 자료를 요약, 매핑, 체크리스트, 프롬프트 형태로 재가공한 작업 지식 영역이다.

## 현재 정리 상태

- 기존 `hexstrike-ai`는 `app/scanner/hexstrike-ai`로 이동했다.
- 기존 루트 `real_fixtures`는 `data/fixtures/real_fixtures`로 이동했다.
- `reporting_starter_v3_package`는 `app/reporting/reporting_starter_v3_package`로 이동했다.
- 기존 한글 폴더 `보고서`는 하드코딩된 경로 참조 가능성을 고려해 유지했다.

## TODO 메모

- `보고서` 하위 `artifacts`, `outputs`를 `reports` 체계로 완전히 통합할 수 있는지 코드 참조를 점검할 것
- `app/reporting/reporting_starter_v3_package/real_fixtures`와 `data/fixtures/real_fixtures`의 중복 역할을 정리할 것
