# Customer Security Assessment Report (Internal)

> Final customer submission package
> 본 문서는 자동 분석 결과를 기반으로 작성되었으며 최종 제출 전 analyst review가 필요합니다.

## 1. 표지 및 문서 정보
- project_name: `Web Vulnerability Assessment`
- client_name: `Internal Client`
- engagement_name: `Security Review`
- analyst_name: `Analyst Team`
- organization_name: `Security Operations`
- report_version: `v1.0`
- delivery_date: `2026-03-15`
- approver_name: `TBD`
- contact_email: `security@example.local`
- run_id: `phase11-pptx-bundle-demo`
- compared_run_id: `N/A`
- run_mode: `single`
- generated_at: `2026-03-15T09:26:03+00:00`

## 2. 실행 정보
- 입력 파일 수: 3
- 입력 파일: `D:\취약점 진단\data\inputs\burp\burp_sample.xml`
- 입력 파일: `D:\취약점 진단\data\inputs\nuclei\nuclei_sample.jsonl`
- 입력 파일: `D:\취약점 진단\data\inputs\httpx\httpx_sample.jsonl`

## 4. Executive Summary
내부 검토용으로 기술 근거와 운영 판단 포인트를 함께 정리했습니다. 이번 실행에서는 총 2건의 보고 대상 이슈가 확인되었고 High 이상은 1건입니다. 우선 조치 대상은 Confirmed SQL Injection, Reflected XSS (Needs Developer Fix)이며, 현재 1개 자산 범위에서 영향이 확인되었습니다. false positive 1건은 본문에서 제외했습니다. suppression 0건은 운영 기준에 따라 별도 관리합니다. 본 결과는 analyst review가 필요한 자동 분석 산출물입니다. 추가 근거와 재현 검토를 전제로 해석하는 것이 적절합니다.

## 5. Severity 통계

| Level | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

## 6. Weakness Family 통계

| Weakness Family | Count |
|---|---:|
| SQL Injection | 1 |
| XSS | 1 |

## 7. 자산별 Findings 요약

| Asset | Issues |
|---|---|
| demo.example.com | I-0001 (High), I-0002 (Medium) |

## 8. 조치 우선순위 및 실행 계획
### 즉시 조치 권고
- Use parameterized queries.
- 출력 위치별 인코딩 규칙을 적용합니다.

### 단기 개선
- 입력값 형식 검증과 최소 권한 DB 계정을 함께 적용합니다.
- CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.

### 중장기 개선
- 입력값이 쿼리 문자열에 직접 연결되는지 확인합니다.
- 에러 메시지, 응답 차이, 비정상 데이터 노출 여부를 확인합니다.
- 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.
- 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.

## 9. Remediation Plan

| Issue ID | Title | Severity | Immediate Action | Structural Fix | Validation After Fix | Owner | Target Due |
|---|---|---|---|---|---|---|---|
| I-0001 | Confirmed SQL Injection | High | Use parameterized queries. | 입력값 형식 검증과 최소 권한 DB 계정을 함께 적용합니다. | 입력값이 쿼리 문자열에 직접 연결되는지 확인합니다.; 에러 메시지, 응답 차이, 비정상 데이터 노출 여부를 확인합니다. | - | - |
| I-0002 | Reflected XSS (Needs Developer Fix) | Medium | 출력 위치별 인코딩 규칙을 적용합니다. | CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다. | 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.; 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다. | - | - |

## 10. 상세 Findings
### I-0001. Confirmed SQL Injection
- 한 줄 요약: Confirmed SQL Injection 이슈가 demo.example.com 자산에서 확인되었으며 우선 조치가 권고됩니다.
- 영향 자산: demo.example.com
- Severity / Confidence: `High (8.7) / High (0.98)`
- CWE / OWASP / KISA: `CWE-89` / `A03 Injection` / `입력값 검증 취약점`
- 개요: 사용자 입력이 SQL 구문으로 해석되어 의도하지 않은 데이터 조회나 변경이 발생할 수 있는 취약점입니다.
- 왜 문제인지: 인증 우회, 민감정보 조회, 데이터 변조로 이어질 수 있어 업무 영향이 큽니다.
- 증거 요약: Captured HTTP request from Burp issue export.; artifact: .tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\raw\burp_001_sql-injection_request.txt; artifact: .tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\redacted\burp_001_sql-injection_request.txt
- 재현/확인 포인트: Replay the saved request artifact against the same endpoint.; .tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\raw\burp_001_sql-injection_request.txt; HTTP/1.1 500 Internal Server Error; .tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\raw\burp_001_sql-injection_response.txt
- 영향: 현재 클러스터 기준으로 1개 자산, 1개 인스턴스에 영향이 있습니다.
- 즉시 조치: Use parameterized queries.
- 근본 개선: 입력값 형식 검증과 최소 권한 DB 계정을 함께 적용합니다.
- 조치 후 확인사항: 입력값이 쿼리 문자열에 직접 연결되는지 확인합니다.; 에러 메시지, 응답 차이, 비정상 데이터 노출 여부를 확인합니다.
- 실무 주의사항: 동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다.
- Reference Labels: CWE-89, OWASP Top 10 2025 A03, KISA 웹 입력값 검증 항목
- 비고: Manually confirmed with replay.

### I-0002. Reflected XSS (Needs Developer Fix)
- 한 줄 요약: Reflected XSS (Needs Developer Fix) 이슈가 demo.example.com 자산에서 확인되었으며 우선 조치가 권고됩니다.
- 영향 자산: demo.example.com
- Severity / Confidence: `Medium (6.0) / Medium (0.8)`
- CWE / OWASP / KISA: `CWE-79` / `A03 Injection` / `스크립트 실행`
- 개요: 사용자 입력이 적절히 인코딩되지 않고 브라우저에 반영되어 스크립트 실행이 가능해지는 취약점입니다.
- 왜 문제인지: 세션 탈취, 화면 변조, 사용자 행위 대행으로 이어질 수 있습니다.
- 증거 요약: Nuclei request captured in result output.; artifact: .tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt; artifact: .tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\redacted\nuclei_002_reflected-xss_request.txt
- 재현/확인 포인트: .tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt; HTTP/1.1 200 OK; Content-Type: text/html; .tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_002_reflected-xss_response.txt
- 영향: 현재 클러스터 기준으로 1개 자산, 1개 인스턴스에 영향이 있습니다.
- 즉시 조치: 출력 위치별 인코딩 규칙을 적용합니다.
- 근본 개선: CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.
- 조치 후 확인사항: 입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.; 보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.
- 실무 주의사항: 동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다.
- Reference Labels: CWE-79, OWASP Top 10 2025 A03, KISA 스크립트 실행 항목
- 비고: User-controlled payload is reflected without encoding.

## 11. QA Metrics

- input_file_count: 3
- parsed_finding_count: 3
- normalized_finding_count: 3
- issue_count: 2
- suppressed_count: 0
- false_positive_count: 0
- overridden_count: 3
- unmapped_cwe_count: 0
- low_confidence_count: 0
- high_severity_count: 1
- evidence_missing_count: 0
- review_queue_count: 1
- packaging_success: False
- qa_warnings:
  - no comparison baseline available
  - rule conflicts observed during mapping

## 12. 부록
### Override 적용 내역
- F-0001
- F-0002
- I-0002

### False Positive 목록
- `F-0002` directory listing

### Suppressed / Accepted Risk 목록
- 없음

### Artifact 참조 인덱스
- F-0001 request: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\raw\burp_001_sql-injection_request.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\redacted\burp_001_sql-injection_request.txt`
- F-0001 response: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\raw\burp_001_sql-injection_response.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\burp\redacted\burp_001_sql-injection_response.txt`
- F-0002 request: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_001_directory-listing_request.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\redacted\nuclei_001_directory-listing_request.txt`
- F-0002 response: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_001_directory-listing_response.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\redacted\nuclei_001_directory-listing_response.txt`
- F-0003 request: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_002_reflected-xss_request.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\redacted\nuclei_002_reflected-xss_request.txt`
- F-0003 response: raw=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\raw\nuclei_002_reflected-xss_response.txt` redacted=`.tmp_run11\phase11-pptx-bundle-demo\artifacts\nuclei\redacted\nuclei_002_reflected-xss_response.txt`

### Decision Trace 요약
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\final_report_bundle.json`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\mapping_decisions.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\scoring_decisions.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\override_decisions.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\cluster_decisions.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\suppression_decisions.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\review_queue.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\review_resolution_applied.jsonl`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\review_closure_status.json`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\qa_metrics.json`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\remediation_policy_decisions.json`
- `.tmp_run11\phase11-pptx-bundle-demo\report_data\ingest_manifest.json`
