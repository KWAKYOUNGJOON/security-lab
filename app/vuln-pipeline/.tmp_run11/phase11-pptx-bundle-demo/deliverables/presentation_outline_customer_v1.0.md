# Presentation Outline

## Customer Security Assessment Report
- Final customer submission package

## Project Overview
- 고객 공유를 위해 핵심 영향과 우선 조치 사항 중심으로 정리했습니다. 이번 실행에서는 총 2건의 보고 대상 이슈가 확인되었고 High 이상은 1건입니다. 우선 조치 대상은 Confirmed SQL Injection, Reflected XSS (Needs Developer Fix)이며, 현재 1개 자산 범위에서 영향이 확인되었습니다. false positive 1건은 본문에서 제외했습니다. suppression 0건은 운영 기준에 따라 별도 관리합니다. 본 결과는 analyst review가 필요한 자동 분석 산출물입니다. 고객 공유용으로는 핵심 영향과 개선 우선순위 중심으로 정리했습니다.

## Scope and Inputs
- Input files: 3 / Affected assets: 1

## Assessment Summary
- Issues: 2 / Unresolved review: 1

## Top Risks
- I-0001 Confirmed SQL Injection (High)
- I-0002 Reflected XSS (Needs Developer Fix) (Medium)

## Action Plan
- {'즉시 조치 권고': ['Use parameterized queries.', '출력 위치별 인코딩 규칙을 적용합니다.'], '단기 개선': ['입력값 형식 검증과 최소 권한 DB 계정을 함께 적용합니다.', 'CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.'], '중장기 개선': ['입력값이 쿼리 문자열에 직접 연결되는지 확인합니다.', '에러 메시지, 응답 차이, 비정상 데이터 노출 여부를 확인합니다.', '입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.', '보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.']}

## Baseline Comparison
- {'new': 0, 'resolved': 0, 'changed': 0, 'unchanged': 0}

## Readiness and Next Steps
- Delivery should be held until blocking items are resolved.
