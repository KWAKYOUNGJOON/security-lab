# reporting_starter_v3

HexStrike AI, Kali, Burp, nuclei, ffuf, httpx, Nikto 등의 웹 취약점 진단 결과를 공통 JSON 스키마로 정규화하고 Markdown/DOCX 보고서를 생성하는 패키지입니다.

목표는 완전 무인 최종본이 아니라 자동 초안 생성 + 사람 검토입니다.

## 운영 구조

- 원본 결과 저장소: `D:\취약점 진단\outputs`
- 보고서 산출물 저장소: `D:\취약점 진단\보고서\artifacts`
- 코드 작업 위치: `D:\취약점 진단\보고서\reporting_starter_v3_package`
- 진단 결과는 반드시 `outputs\run_YYYY-MM-DD_NNN` 폴더에 저장합니다.
- 보고서 엔진은 `outputs` 아래 run 폴더를 직접 읽습니다.
- 원본 결과를 별도 폴더로 다시 복사하지 않습니다.
- 생성 결과는 `보고서\artifacts\<run폴더명>`에 저장합니다.

## 빠른 시작

```bash
pip install -r requirements.txt
python self_check.py
python -m pytest -q
```

## 권장 run 폴더 구조

```text
D:\취약점 진단\outputs\run_2026-03-15_001
├─ nuclei.jsonl
├─ ffuf.json
├─ httpx.jsonl
├─ nikto.json
├─ burp.xml
├─ notes.txt
└─ screenshots\
```

하위 폴더에 저장해도 자동 탐지는 가능하지만, 운영 단순성을 위해 가능하면 run 폴더 루트에 두는 것을 권장합니다.

## 도구별 권장 파일명

- `nuclei`: `nuclei.jsonl`
- `ffuf`: `ffuf.json`
- `httpx`: `httpx.jsonl`
- `nikto`: `nikto.json`
- `burp`: `burp.xml`

자동 탐지는 아래 패턴을 우선 사용합니다.

- `*nuclei*.jsonl`
- `*ffuf*.json`
- `*httpx*.jsonl`
- `*nikto*.json`
- `*burp*.xml`

같은 유형 후보가 여러 개면 파일명 일치, 더 얕은 경로, 더 큰 파일 순으로 우선합니다.

## run 폴더 생성 보조 스크립트

새 run 폴더를 만들려면:

```bat
scripts\create_run_folder.bat
```

기본 생성 위치:

```text
D:\취약점 진단\outputs\run_YYYY-MM-DD_NNN
```

생성 시 함께 준비되는 항목:

- `screenshots\`
- `notes.txt`

원하면 출력 루트를 직접 지정할 수 있습니다.

```bat
scripts\create_run_folder.bat "D:\취약점 진단\outputs"
```

## Windows 기준 결과 수집 예시

아래 예시는 run 폴더에 스캐너 결과를 직접 저장하는 방식입니다.

### nuclei

```bat
nuclei -u https://target.example -jsonl -o "D:\취약점 진단\outputs\run_2026-03-15_001\nuclei.jsonl"
```

### ffuf

```bat
ffuf -u https://target.example/FUZZ -w wordlist.txt -of json -o "D:\취약점 진단\outputs\run_2026-03-15_001\ffuf.json"
```

### httpx

```bat
httpx -u https://target.example -json -o "D:\취약점 진단\outputs\run_2026-03-15_001\httpx.jsonl"
```

### nikto

```bat
nikto -h https://target.example -Format json -output "D:\취약점 진단\outputs\run_2026-03-15_001\nikto.json"
```

### burp

Burp Scanner 결과를 XML로 export 해서 아래 경로에 저장합니다.

```text
D:\취약점 진단\outputs\run_2026-03-15_001\burp.xml
```

스크린샷은 필요하면 아래에 저장합니다.

```text
D:\취약점 진단\outputs\run_2026-03-15_001\screenshots\
```

메모는 아래 파일에 정리합니다.

```text
D:\취약점 진단\outputs\run_2026-03-15_001\notes.txt
```

## 파이프라인 실행

명시적으로 산출물 경로를 주는 경우:

```bash
python pipeline.py ^
  --target https://target.example ^
  --author analyst ^
  --run-dir "D:\취약점 진단\outputs\run_2026-03-15_001" ^
  --include-banner ^
  --docx ^
  --output-dir "D:\취약점 진단\보고서\artifacts\run_2026-03-15_001"
```

`--output-dir`를 생략하면 아래로 자동 저장됩니다.

```bash
python pipeline.py ^
  --target https://target.example ^
  --author analyst ^
  --run-dir "D:\취약점 진단\outputs\run_2026-03-15_001" ^
  --include-banner ^
  --docx
```

기본 산출물 경로:

```text
D:\취약점 진단\보고서\artifacts\run_2026-03-15_001
```

배치 스크립트 사용 예시:

```bat
scripts\run_outputs_pipeline.bat "D:\취약점 진단\outputs\run_2026-03-15_001" "https://target.example" analyst
```

## 개별 파일 옵션 유지

기존 옵션도 그대로 사용할 수 있습니다.

- `--nuclei`
- `--burp`
- `--ffuf`
- `--httpx`
- `--nikto`

필요하면 `--run-dir`와 개별 옵션을 함께 쓰고, 개별 옵션이 우선합니다.

## 테스트 범위

```bash
python -m pytest -q
```

포함 범위:

- severity 엔진
- merge / dedupe
- override 적용
- render context
- sample fixture 기반 파이프라인
- `run-dir` 자동 탐지 및 기본 출력 경로
- `real_fixtures` 기반 parser fixture
