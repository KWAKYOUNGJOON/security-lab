# Report Generation Prompt Draft

다음 스캔 결과와 수동 점검 메모를 바탕으로 웹 취약점 진단 보고서 초안을 작성하라.

## 입력 자료

- 정규화된 취약점 JSON
- 원본 스캐너 결과(JSON/XML/TXT)
- Burp export
- 수동 점검 메모
- 기준 문서 요약(OWASP, KISA, 내부 체크리스트)

## 작성 요구사항

1. 자산 개요와 진단 범위를 먼저 요약한다.
2. 취약점은 심각도 기준으로 정렬한다.
3. 각 취약점마다 제목, 설명, 영향도, 재현 절차, 증거, 대응 방안을 작성한다.
4. 가능한 경우 OWASP와 KISA 매핑을 함께 제시한다.
5. 중복 결과는 하나로 병합하고, 도구별 증거는 분리해 정리한다.
6. 확실하지 않은 내용은 추정이라고 명시한다.
7. 출력은 Markdown 본문 기준으로 작성하되 Docx 변환에 적합한 헤더 구조를 유지한다.

## 출력 형식

- Executive Summary
- Scope and Method
- Findings Summary Table
- Detailed Findings
- Remediation Priorities
- Appendix: Evidence and Tool Notes

## 주의사항

- 존재하지 않는 취약점을 만들어내지 말 것
- 민감정보는 마스킹할 것
- 재현 절차는 과도하게 공격적인 문장보다 검증 가능한 절차 중심으로 작성할 것
