# Presentation Outline

## Presentation Briefing
- x / y

## Project Overview
- 고객 공유를 위해 핵심 영향과 우선 조치 사항 중심으로 정리했습니다. 이번 실행에서는 총 3건의 보고 대상 이슈가 확인되었고 High 이상은 1건입니다. 우선 조치 대상은 error disclosure, reflected xss, potential input reflection이며, 현재 1개 자산 범위에서 영향이 확인되었습니다. false positive 1건은 본문에서 제외했습니다. suppression 0건은 운영 기준에 따라 별도 관리합니다. 본 결과는 analyst review가 필요한 자동 분석 산출물입니다. 고객 공유용으로는 핵심 영향과 개선 우선순위 중심으로 정리했습니다.

## Scope and Inputs
- Input files: 3 / Affected assets: 1

## Assessment Summary
- Issues: 3 / Unresolved review: 3

## Top Risks
- I-0001 error disclosure (Low)
- I-0002 reflected xss (Medium)
- I-0003 potential input reflection (High)

## Action Plan
- {'즉시 조치 권고': ['운영 환경 상세 오류 응답을 비활성화합니다.', '출력 위치별 인코딩 규칙을 적용합니다.', '모든 객체 접근에 대해 소유권/역할 기반 검사를 수행합니다.'], '단기 개선': ['상세 로그는 내부 로깅 채널로만 남기고 운영 디버그 기능을 비활성화합니다.', 'CSP, 템플릿 자동 이스케이프, 입력값 검증을 함께 적용합니다.', '예측 가능한 식별자 사용을 줄이고 서버 측 권한 검사를 일관화합니다.'], '중장기 개선': ['예외 발생 시 상세 경로, SQL 오류, 프레임워크 버전이 노출되는지 확인합니다.', '운영 환경에서 디버그 모드가 비활성화되어 있는지 확인합니다.', '입력값이 HTML, 속성, 스크립트 컨텍스트에 그대로 반영되는지 확인합니다.', '보안 헤더와 템플릿 인코딩 정책이 일관되게 적용되는지 확인합니다.', 'URL, 파라미터, 본문 내 식별자를 변경해도 서버가 권한을 다시 검증하는지 확인합니다.']}

## Baseline Comparison
- {'new': 0, 'resolved': 0, 'changed': 0, 'unchanged': 0}

## Readiness and Next Steps
- Delivery is possible after reviewing warning items.
