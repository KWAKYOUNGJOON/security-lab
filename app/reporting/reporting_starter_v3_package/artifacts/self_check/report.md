# 웹 취약점 진단 보고서

## 1. 보고 개요
- 프로젝트명: https://www.example.org 웹 취약점 진단 보고서
- 대상: https://www.example.org
- 생성 시각: 2026-03-15T03:09:36.678008+09:00
- 고객사/기관: -
- 작성자: self-check

## 2. 점검 범위
- 웹 애플리케이션
- 웹 서버 설정
- 자동 진단 결과
- Burp 점검 결과
- 경로 탐색
- 웹 서비스 프로브
- 웹 서버 점검

## 3. 기준
- KISA 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드
- OWASP 기준: OWASP Top 10

## 4. 결과 요약
- 전체 취약점 수: 9
- Critical: 0
- High: 2
- Medium: 5
- Low: 0
- Info: 2

## 5. 취약점 상세
### WEB-001. 보안 헤더 미설정
- 분류: 보안설정
- 위험도: MEDIUM
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org
- URL: https://www.example.org/
- 파라미터: -
- 도구: nuclei

#### 설명
Target is missing one or more recommended security headers.

#### 영향
자동 진단 결과이므로 실제 영향도와 악용 가능성은 수동 검증으로 확정해야 합니다.

#### 위험도 판단 근거
- nuclei severity: medium
- template-id: http-missing-security-headers

#### 재현 절차
1. 원본 nuclei 결과에서 탐지 URL과 matcher 이름을 확인합니다.
2. 동일한 요청을 재현해 응답이 반복되는지 수동 검증합니다.

#### 증거
- [text] matched-at: https://www.example.org/- [text] matcher-name: x-frame-options- [http_request] GET / HTTP/1.1
Host: www.example.org
User-Agent: nuclei- [http_response] HTTP/1.1 200 OK
Content-Type: text/html

<html>...</html>
#### 권고 사항
- 탐지된 항목이 실제 노출인지 먼저 수동으로 확인합니다.
- 불필요한 엔드포인트, 설정, 노출 정보를 제거하거나 접근을 제한합니다.
- 관련 서버와 애플리케이션을 최신 보안 설정 기준에 맞게 점검합니다.

#### 참고 분류
- OWASP: A05
- KISA: III. 서비스 구성 > 보안 설정

### WEB-002. 외부 도메인으로의 Referer 정보 노출
- 분류: 정보노출
- 위험도: MEDIUM
- 신뢰도: HIGH
- 상태: needs_review
- 자산: https://www.example.org:443
- URL: https://www.example.org/login
- 파라미터: -
- 도구: burp

#### 설명
Referrer leakage may disclose sensitive paths.

#### 영향
애플리케이션 구현 또는 설정 문제로 인해 정보 노출이나 보안 통제 우회 위험이 존재할 수 있습니다.

#### 위험도 판단 근거
- burp severity: medium
- burp confidence: high

#### 재현 절차
1. Burp 원본 이슈의 위치와 요청/응답을 확인합니다.
2. 동일한 요청을 Repeater 등으로 재전송해 결과가 반복되는지 검증합니다.

#### 증거
- [http_request] GET /login HTTP/1.1
Host: www.example.org- [http_response] HTTP/1.1 200 OK
Content-Type: text/html

<html>...</html>- [text] location: https://www.example.org/login
#### 권고 사항
- Use an appropriate Referrer-Policy header.
- 영향 범위와 악용 가능성을 수동 검증해 최종 위험도를 확정합니다.

#### 참고 분류
- OWASP: A02
- KISA: III. 서비스 구성 > 보안 설정

### WEB-003. 관리자 또는 민감 경로 발견
- 분류: 노출경로
- 위험도: MEDIUM
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org/admin
- URL: https://www.example.org/admin
- 파라미터: -
- 도구: ffuf

#### 설명
ffuf 디렉터리/파일 탐색 결과, 주목할 만한 경로가 응답한 것이 확인되었습니다.

#### 영향
민감 경로나 파일이 노출된 경우 관리자 인터페이스 접근, 설정 정보 노출, 추가 공격면 탐색 위험이 존재합니다.

#### 위험도 판단 근거
- ffuf status: 200
- 유효한 응답으로 판단된 경로

#### 재현 절차
1. 브라우저 또는 curl로 https://www.example.org/admin 경로에 직접 접근합니다.
2. 동일한 상태 코드와 응답 본문이 재현되는지 확인합니다.

#### 증거
- [text] url: https://www.example.org/admin- [text] status: 200- [text] size: 1324 bytes- [text] input: {"FUZZ": "admin"}
#### 권고 사항
- 불필요한 민감 경로와 파일은 제거하거나 외부 접근을 차단합니다.
- 관리자 인터페이스에는 접근통제와 인증 강화를 적용합니다.
- 운영 중 필요한 경로인지 서비스 담당자와 함께 검토합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-004. 민감 파일 또는 백업 파일 노출 가능성
- 분류: 정보노출
- 위험도: HIGH
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org/.env
- URL: https://www.example.org/.env
- 파라미터: -
- 도구: ffuf

#### 설명
ffuf 디렉터리/파일 탐색 결과, 주목할 만한 경로가 응답한 것이 확인되었습니다.

#### 영향
민감 경로나 파일이 노출된 경우 관리자 인터페이스 접근, 설정 정보 노출, 추가 공격면 탐색 위험이 존재합니다.

#### 위험도 판단 근거
- ffuf status: 200
- 유효한 응답으로 판단된 경로

#### 재현 절차
1. 브라우저 또는 curl로 https://www.example.org/.env 경로에 직접 접근합니다.
2. 동일한 상태 코드와 응답 본문이 재현되는지 확인합니다.

#### 증거
- [text] url: https://www.example.org/.env- [text] status: 200- [text] size: 84 bytes- [text] input: {"FUZZ": ".env"}
#### 권고 사항
- 불필요한 민감 경로와 파일은 제거하거나 외부 접근을 차단합니다.
- 관리자 인터페이스에는 접근통제와 인증 강화를 적용합니다.
- 운영 중 필요한 경로인지 서비스 담당자와 함께 검토합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-005. 서버 배너 정보 노출
- 분류: 정보노출
- 위험도: INFO
- 신뢰도: HIGH
- 상태: needs_review
- 자산: https://www.example.org
- URL: https://www.example.org
- 파라미터: -
- 도구: httpx

#### 설명
응답 헤더 또는 프로브 결과에서 웹 서버 식별 정보가 노출되었습니다.

#### 영향
직접적인 취약점은 아니지만 공격자가 서버 종류와 버전을 추정하는 데 활용할 수 있습니다.

#### 위험도 판단 근거
- server banner: nginx/1.24.0

#### 재현 절차
1. curl -I https://www.example.org 명령으로 응답 헤더를 확인합니다.
2. Server 헤더 또는 유사한 식별 정보 노출 여부를 검증합니다.

#### 증거
- [text] url: https://www.example.org- [text] server: nginx/1.24.0
#### 권고 사항
- 불필요한 서버 배너와 상세 버전 정보 노출을 최소화합니다.
- 프록시 또는 웹 서버 설정에서 헤더 마스킹을 검토합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-006. 관리자 또는 인증 경로 노출
- 분류: 노출경로
- 위험도: MEDIUM
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org/admin
- URL: https://www.example.org/admin
- 파라미터: -
- 도구: httpx

#### 설명
httpx 결과에서 관리자 또는 인증 관련 경로가 외부에서 식별되었습니다.

#### 영향
관리자 인터페이스나 인증 페이지가 노출된 경우 계정 추측, 브루트포스, 추가 기능 탐색 가능성이 증가합니다.

#### 위험도 판단 근거
- httpx status_code: 200
- 민감 경로 키워드와 일치

#### 재현 절차
1. 브라우저에서 https://www.example.org/admin 에 접속합니다.
2. 동일한 상태 코드와 페이지 제목이 반복되는지 확인합니다.

#### 증거
- [text] url: https://www.example.org/admin- [text] title: Admin Login
#### 권고 사항
- 관리자 및 인증 경로에는 접근통제를 적용합니다.
- IP 제한, MFA, 접근 로그 강화를 검토합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-007. 서버 배너 정보 노출
- 분류: 정보노출
- 위험도: INFO
- 신뢰도: HIGH
- 상태: needs_review
- 자산: https://www.example.org/admin
- URL: https://www.example.org/admin
- 파라미터: -
- 도구: httpx

#### 설명
응답 헤더 또는 프로브 결과에서 웹 서버 식별 정보가 노출되었습니다.

#### 영향
직접적인 취약점은 아니지만 공격자가 서버 종류와 버전을 추정하는 데 활용할 수 있습니다.

#### 위험도 판단 근거
- server banner: nginx/1.24.0

#### 재현 절차
1. curl -I https://www.example.org/admin 명령으로 응답 헤더를 확인합니다.
2. Server 헤더 또는 유사한 식별 정보 노출 여부를 검증합니다.

#### 증거
- [text] url: https://www.example.org/admin- [text] server: nginx/1.24.0
#### 권고 사항
- 불필요한 서버 배너와 상세 버전 정보 노출을 최소화합니다.
- 프록시 또는 웹 서버 설정에서 헤더 마스킹을 검토합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-008. 보안 헤더 미설정
- 분류: 보안설정
- 위험도: MEDIUM
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org/
- URL: https://www.example.org/
- 파라미터: -
- 도구: nikto

#### 설명
The anti-clickjacking X-Frame-Options header is not present.

#### 영향
Nikto 결과는 웹 서버 또는 애플리케이션 구성에 대해 추가 보안 검토가 필요함을 의미합니다.

#### 위험도 판단 근거
- nikto id: 999978
- Nikto JSON 결과 기반

#### 재현 절차
1. GET 요청으로 / 경로를 확인합니다.
2. 동일한 메시지 또는 관련 설정 상태가 재현되는지 검증합니다.

#### 증거
- [text] url: /- [text] message: The anti-clickjacking X-Frame-Options header is not present.- [text] references: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
#### 권고 사항
- 탐지된 설정 또는 노출 항목이 실제 위험인지 수동 검증합니다.
- 불필요한 테스트 페이지, 진단 페이지, 민감 파일은 제거하거나 접근을 제한합니다.
- 권장 보안 헤더와 최신 서버 구성을 적용합니다.

#### 참고 분류
- OWASP: -
- KISA: -

### WEB-009. 민감 파일 또는 기능 노출
- 분류: 정보노출
- 위험도: HIGH
- 신뢰도: MEDIUM
- 상태: needs_review
- 자산: https://www.example.org/phpinfo.php
- URL: https://www.example.org/phpinfo.php
- 파라미터: -
- 도구: nikto

#### 설명
phpinfo() file found.

#### 영향
Nikto 결과는 웹 서버 또는 애플리케이션 구성에 대해 추가 보안 검토가 필요함을 의미합니다.

#### 위험도 판단 근거
- nikto id: 999999
- Nikto JSON 결과 기반

#### 재현 절차
1. GET 요청으로 /phpinfo.php 경로를 확인합니다.
2. 동일한 메시지 또는 관련 설정 상태가 재현되는지 검증합니다.

#### 증거
- [text] url: /phpinfo.php- [text] message: phpinfo() file found.- [text] references: https://www.php.net/manual/en/function.phpinfo.php
#### 권고 사항
- 탐지된 설정 또는 노출 항목이 실제 위험인지 수동 검증합니다.
- 불필요한 테스트 페이지, 진단 페이지, 민감 파일은 제거하거나 접근을 제한합니다.
- 권장 보안 헤더와 최신 서버 구성을 적용합니다.

#### 참고 분류
- OWASP: -
- KISA: -

