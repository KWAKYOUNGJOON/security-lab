# real_fixtures

실제 운영 도구 출력 샘플을 보관하기 위한 폴더입니다.

## naming 규칙

- 입력 파일: `<case_name>.input.<ext>`
- 메타 파일: `<case_name>.meta.json`
- 기대값 파일: `<case_name>.expected.json`

예시:

- `customer_a_20260315.input.jsonl`
- `customer_a_20260315.meta.json`
- `customer_a_20260315.expected.json`

## 메타 파일 규칙

```json
{
  "target": "https://target.example",
  "author": "fixture-test",
  "mapping": true,
  "extra_args": []
}
```

- `mapping`: 매핑 파일 자동 연결 여부
- `extra_args`: parser CLI에 추가할 인자 배열

## 기대값 파일 규칙

```json
{
  "min_findings": 1,
  "contains_titles": ["보안 헤더 미설정"]
}
```

이 폴더의 fixture는 `pytest`에서 sample fixture와 함께 검증됩니다.
