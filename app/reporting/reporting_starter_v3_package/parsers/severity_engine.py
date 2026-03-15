from __future__ import annotations

from typing import Any


NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

BURP_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}


def map_nuclei_severity(value: str | None) -> str:
    return NUCLEI_SEVERITY_MAP.get((value or "").lower(), "info")


def map_burp_severity(value: str | None) -> str:
    return BURP_SEVERITY_MAP.get((value or "").lower(), "info")


def classify_ffuf_result(url: str, status: int) -> tuple[str, str, str]:
    lower = url.lower()
    if any(keyword in lower for keyword in [".env", ".git", "backup", ".bak", "config", "phpinfo"]):
        return ("민감 파일 또는 백업 파일 노출 가능성", "정보노출", "high" if status == 200 else "medium")
    if any(keyword in lower for keyword in ["admin", "wp-admin", "phpmyadmin", "dashboard", "manage", "manager"]):
        return ("관리자 또는 민감 경로 발견", "노출경로", "medium")
    if any(keyword in lower for keyword in ["login", "signin", "auth"]):
        return ("인증 관련 경로 발견", "노출경로", "low")
    return ("의미 있는 경로 발견", "노출경로", "info")


def classify_httpx_path(url: str, status: int) -> tuple[str, str, str] | None:
    lower = url.lower()
    keywords = ["admin", "login", "dashboard", "manage", "manager", "wp-admin", "phpmyadmin"]
    if not any(keyword in lower for keyword in keywords):
        return None
    if status < 200 or status >= 500:
        return None
    severity = "medium" if status in (200, 401, 403) else "low"
    return ("관리자 또는 인증 경로 노출", "노출경로", severity)


def classify_nikto_message(message: str, url: str) -> tuple[str, str, str]:
    lower = f"{message} {url}".lower()
    if "phpinfo" in lower or ".git" in lower or ".env" in lower or "backup" in lower:
        return ("민감 파일 또는 기능 노출", "정보노출", "high")
    if "x-frame-options" in lower or "content-security-policy" in lower or "x-content-type-options" in lower:
        return ("보안 헤더 미설정", "보안설정", "medium")
    if "directory indexing" in lower or "indexing" in lower:
        return ("디렉터리 인덱싱 노출", "정보노출", "medium")
    if "version" in lower or "banner" in lower:
        return ("서버 또는 소프트웨어 버전 노출", "정보노출", "low")
    return ("Nikto 점검 항목", "자동진단", "low")


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in {"critical", "high", "medium", "low", "info"} else "info"
