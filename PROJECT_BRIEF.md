# PROJECT BRIEF

## 프로젝트 목적

웹 취약점 자동 분석 및 보고서 생성.

## 입력

- 스캐너 결과: JSON, XML, TXT
- Burp export
- 수동 점검 메모

## 출력

- Markdown 보고서
- Docx 보고서
- PDF 보고서

## 기준

- OWASP
- KISA
- 내부 체크리스트

## 우선 구현 범위

- parser
- context builder
- report generator
- docx output
- fixture 기반 테스트

## 현재 구조 메모

- 스캐너 코드는 `app/scanner/hexstrike-ai`
- 보고서 패키지는 `app/reporting/reporting_starter_v3_package`
- 원본 참고자료는 `reference`, 재가공 지식은 `knowledge`

## 후속 TODO

- `보고서` 폴더의 기존 산출물 경로를 `reports` 체계로 이관 가능한지 검토
- 보고서 패키지 내부 fixture 경로와 루트 `data/fixtures` 간 기준 경로를 하나로 통합
