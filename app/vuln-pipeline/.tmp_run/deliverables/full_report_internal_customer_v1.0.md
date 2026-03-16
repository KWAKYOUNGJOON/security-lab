# 웹 취약점 진단 보고서 (Internal)

> 내부 분석용 상세 보고서
> 본 문서는 자동 분석 결과를 기반으로 작성되었으며 최종 제출 전 analyst review가 필요합니다.

## 1. 표지 및 문서 정보
- project_name: `x`
- client_name: `y`
- engagement_name: `z`
- analyst_name: `a`
- organization_name: `o`
- report_version: `v1.0`
- delivery_date: `2026-03-15`
- approver_name: `TBD`
- contact_email: `security@example.local`
- run_id: `smoke`
- compared_run_id: `N/A`
- run_mode: `single`
- generated_at: `2026-03-15T06:35:23+00:00`

## 2. 실행 정보
- 입력 파일 수: 3
- 입력 파일: `D:\취약점 진단\app\vuln-pipeline\tests\fixtures\realish\burp_complex.xml`
- 입력 파일: `D:\취약점 진단\app\vuln-pipeline\tests\fixtures\realish\nuclei_rich.jsonl`
- 입력 파일: `D:\취약점 진단\app\vuln-pipeline\tests\fixtures\realish\httpx_rich.jsonl`

## 4. Executive Summary
내부 검토용으로 기술 근거와 운영 판단 포인트를 함께 정리했습니다. 이번 실행에서는 총 3건의 보고 대상 이슈가 확인되었고 High 이상은 1건입니다. 우선 조치 대상은 error disclosure, reflected xss, potential input reflection이며, 현재 1개 자산 범위에서 영향이 확인되었습니다. false positive 1건은 본문에서 제외했습니다. suppression 0건은 운영 기준에 따라 별도 관리합니다. 본 결과는 analyst review가 필요한 자동 분석 산출물입니다. 추가 근거와 재현 검토를 전제로 해석하는 것이 적절합니다.

## 5. Severity 통계

| Level | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |

## 6. Weakness Family 통계

| Weakness Family | Count |
|---|---:|
| Error/Stack Trace Disclosure | 1 |
| IDOR/BOLA | 1 |
| XSS | 1 |

## 7. 자산별 Findings 요약

| Asset | Issues |
|---|---|
| portal.example.com | I-0001 (Low), I-0002 (Medium), I-0003 (High) |

## 8. 조치 우선순위 및 실행 계획
### 즉시 조치 권고
- 운영 환경 상세 오류 응답을 비활성화합니다.
- 출력 위치별 인코딩 규칙을 적용합니다.
- 모든 객체 접근에 대해 소유권/역할 기반 검사를 수행합니다.

### 단기 개선
- 상세 로그는 내부 로깅 채널로만 남기고 운영 디버그 기능을 비활성화합니다.
- CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.
- 예측 가능한 식별자 사용을 줄이고 서버 측 권한 검사를 일관화합니다.

### 중장기 개선
- 예외 발생 시 상세 경로, SQL 오류, 프레임워크 버전이 노출되는지 확인합니다.
- 운영 환경에서 디버그 모드가 비활성화되어 있는지 확인합니다.
- 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.
- 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.
- URL, 파라미터, 본문 내 식별자를 변경해도 서버가 권한을 다시 검증하는지 확인합니다.

## 9. Remediation Plan

| Issue ID | Title | Severity | Immediate Action | Structural Fix | Validation After Fix | Owner | Target Due |
|---|---|---|---|---|---|---|---|
| I-0001 | error disclosure | Low | 운영 환경 상세 오류 응답을 비활성화합니다. | 상세 로그는 내부 로깅 채널로만 남기고 운영 디버그 기능을 비활성화합니다. | 예외 발생 시 상세 경로, SQL 오류, 프레임워크 버전이 노출되는지 확인합니다.; 운영 환경에서 디버그 모드가 비활성화되어 있는지 확인합니다. | - | - |
| I-0002 | reflected xss | Medium | 출력 위치별 인코딩 규칙을 적용합니다. | CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다. | 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.; 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다. | - | - |
| I-0003 | potential input reflection | High | 모든 객체 접근에 대해 소유권/역할 기반 검사를 수행합니다. | 예측 가능한 식별자 사용을 줄이고 서버 측 권한 검사를 일관화합니다. | URL, 파라미터, 본문 내 식별자를 변경해도 서버가 권한을 다시 검증하는지 확인합니다.; 객체 단위 권한 검사가 서비스 계층에서 강제되는지 확인합니다. | - | - |

## 10. 상세 Findings
### I-0001. error disclosure
- 한 줄 요약: error disclosure 이슈가 portal.example.com 자산에서 확인되었으며 우선 조치가 권고됩니다.
- 영향 자산: portal.example.com
- Severity / Confidence: `Low (2.8) / Medium (0.8)`
- CWE / OWASP / KISA: `CWE-209` / `A05 Security Misconfiguration` / `오류 정보 노출`
- 개요: 예외 메시지나 내부 스택 트레이스가 외부 응답에 포함되어 시스템 내부 정보가 노출되는 상태입니다.
- 왜 문제인지: 구조 파악, 추가 공격 단서 확보, 민감 정보 노출로 이어질 수 있습니다.
- 증거 요약: Captured HTTP request from Burp issue export.; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\raw\burp_001_error-disclosure_request.txt; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\redacted\burp_001_error-disclosure_request.txt
- 재현/확인 포인트: Replay the saved request artifact against the same endpoint.; D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\raw\burp_001_error-disclosure_request.txt; HTTP/1.1 500 Internal Server Error; D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\raw\burp_001_error-disclosure_response.txt
- 영향: 현재 클러스터 기준으로 1개 자산, 1개 인스턴스에 영향이 있습니다.
- 즉시 조치: 운영 환경 상세 오류 응답을 비활성화합니다.
- 근본 개선: 상세 로그는 내부 로깅 채널로만 남기고 운영 디버그 기능을 비활성화합니다.
- 조치 후 확인사항: 예외 발생 시 상세 경로, SQL 오류, 프레임워크 버전이 노출되는지 확인합니다.; 운영 환경에서 디버그 모드가 비활성화되어 있는지 확인합니다.
- 실무 주의사항: 동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다.
- Reference Labels: CWE-209, OWASP Top 10 2025 A05, KISA 오류 정보 노출 항목
- 비고: 운영 환경 예외 메시지 노출로 판단되며 즉시 차단이 필요함.

### I-0002. reflected xss
- 한 줄 요약: reflected xss 이슈가 portal.example.com 자산에서 확인되었으며 우선 조치가 권고됩니다.
- 영향 자산: portal.example.com
- Severity / Confidence: `Medium (6.0) / Medium (0.8)`
- CWE / OWASP / KISA: `CWE-79` / `A03 Injection` / `스크립트 실행`
- 개요: 사용자 입력이 적절히 인코딩되지 않고 브라우저에 반영되어 스크립트 실행이 가능해지는 취약점입니다.
- 왜 문제인지: 세션 탈취, 화면 변조, 사용자 행위 대행으로 이어질 수 있습니다.
- 증거 요약: Nuclei request captured in result output.; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_002_reflected-xss_request.txt
- 재현/확인 포인트: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt; HTTP/1.1 200 OK; Content-Type: text/html; D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_002_reflected-xss_response.txt
- 영향: 현재 클러스터 기준으로 1개 자산, 2개 인스턴스에 영향이 있습니다.
- 즉시 조치: 출력 위치별 인코딩 규칙을 적용합니다.
- 근본 개선: CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.
- 조치 후 확인사항: 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.; 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.
- 실무 주의사항: 동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다.
- Reference Labels: CWE-79, OWASP Top 10 2025 A03, KISA 스크립트 실행 항목

### I-0003. potential input reflection
- 한 줄 요약: potential input reflection 이슈가 portal.example.com 자산에서 확인되었으며 우선 조치가 권고됩니다.
- 영향 자산: portal.example.com
- Severity / Confidence: `High (7.4) / Medium (0.8)`
- CWE / OWASP / KISA: `CWE-639` / `A01 Broken Access Control` / `접근통제 미흡`
- 개요: 사용자 식별자나 객체 ID를 변경했을 때 다른 사용자의 자원에 접근할 수 있는 취약점입니다.
- 왜 문제인지: 개인정보 노출, 권한 없는 데이터 변경, 업무 무결성 훼손으로 이어질 수 있습니다.
- 증거 요약: Nuclei request captured in result output.; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_004_potential-input-reflection_request.txt; artifact: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_004_potential-input-reflection_request.txt
- 재현/확인 포인트: D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_004_potential-input-reflection_request.txt; HTTP/1.1 200 OK; Content-Type: text/html; D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_004_potential-input-reflection_response.txt
- 영향: 현재 클러스터 기준으로 1개 자산, 1개 인스턴스에 영향이 있습니다.
- 즉시 조치: 모든 객체 접근에 대해 소유권/역할 기반 검사를 수행합니다.
- 근본 개선: 예측 가능한 식별자 사용을 줄이고 서버 측 권한 검사를 일관화합니다.
- 조치 후 확인사항: URL, 파라미터, 본문 내 식별자를 변경해도 서버가 권한을 다시 검증하는지 확인합니다.; 객체 단위 권한 검사가 서비스 계층에서 강제되는지 확인합니다.
- 실무 주의사항: 동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다.
- Reference Labels: CWE-639, OWASP Top 10 2025 A01, KISA 접근통제 항목

## 11. QA Metrics

- input_file_count: 0
- parsed_finding_count: 5
- normalized_finding_count: 5
- issue_count: 3
- suppressed_count: 0
- false_positive_count: 0
- overridden_count: 2
- unmapped_cwe_count: 0
- low_confidence_count: 0
- high_severity_count: 1
- evidence_missing_count: 0
- review_queue_count: 3
- packaging_success: True
- qa_warnings:
  - no comparison baseline available
  - rule conflicts observed during mapping

## 12. 부록
### Override 적용 내역
- F-0001
- F-0002

### False Positive 목록
- `F-0002` directory listing

### Suppressed / Accepted Risk 목록
- 없음

### Artifact 참조 인덱스
- F-0001 request: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\raw\burp_001_error-disclosure_request.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\redacted\burp_001_error-disclosure_request.txt`
- F-0001 response: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\raw\burp_001_error-disclosure_response.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\burp\redacted\burp_001_error-disclosure_response.txt`
- F-0002 request: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_001_directory-listing_request.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_001_directory-listing_request.txt`
- F-0002 response: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_001_directory-listing_response.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_001_directory-listing_response.txt`
- F-0003 request: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_002_reflected-xss_request.txt`
- F-0003 response: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_002_reflected-xss_response.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_002_reflected-xss_response.txt`
- F-0004 request: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_003_reflected-xss_request.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_003_reflected-xss_request.txt`
- F-0004 response: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_003_reflected-xss_response.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_003_reflected-xss_response.txt`
- F-0005 request: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_004_potential-input-reflection_request.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_004_potential-input-reflection_request.txt`
- F-0005 response: raw=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\raw\nuclei_004_potential-input-reflection_response.txt` redacted=`D:\취약점 진단\app\vuln-pipeline\.tmp_run\artifacts\nuclei\redacted\nuclei_004_potential-input-reflection_response.txt`

### Decision Trace 요약
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\final_report_bundle.json`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\mapping_decisions.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\scoring_decisions.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\override_decisions.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\cluster_decisions.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\suppression_decisions.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\review_queue.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\review_resolution_applied.jsonl`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\review_closure_status.json`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\qa_metrics.json`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\remediation_policy_decisions.json`
- `D:\취약점 진단\app\vuln-pipeline\.tmp_run\report_data\ingest_manifest.json`
