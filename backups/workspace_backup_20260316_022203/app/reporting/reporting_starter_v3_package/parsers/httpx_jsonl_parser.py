#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from common import load_jsonl, make_report_meta, safe_int, safe_str, write_report
from severity_engine import classify_httpx_path


def finding_admin_path(item: Dict[str, Any], idx: int, source_name: str) -> Dict[str, Any] | None:
    url = safe_str(item.get("url"), "") or ""
    status = safe_int(item.get("status_code")) or 0
    classification = classify_httpx_path(url, status)
    if classification is None:
        return None
    title, category, severity = classification

    return {
        "id": f"WEB-{idx:03d}",
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "medium",
        "status": "needs_review",
        "asset": url or safe_str(item.get("input"), "unknown"),
        "host": safe_str(item.get("host")),
        "url": safe_str(item.get("url")),
        "method": "GET",
        "parameter": None,
        "port": safe_int(item.get("port")),
        "description": "httpx 결과에서 관리자 또는 인증 관련 경로가 외부에서 식별되었습니다.",
        "impact": "관리자 인터페이스나 인증 페이지가 노출된 경우 계정 추측, 브루트포스, 추가 기능 탐색 가능성이 증가합니다.",
        "severity_reason": [
            f"httpx status_code: {status}",
            "민감 경로 키워드와 일치",
        ],
        "evidence": [
            {"type": "text", "content": f"url: {item.get('url')}", "path": None},
            {"type": "text", "content": f"title: {item.get('title')}", "path": None},
        ],
        "reproduction_steps": [
            f"브라우저에서 {item.get('url')} 에 접속합니다.",
            "동일한 상태 코드와 페이지 제목이 반복되는지 확인합니다.",
        ],
        "recommendation": [
            "관리자 및 인증 경로에는 접근통제를 적용합니다.",
            "IP 제한, MFA, 접근 로그 강화를 검토합니다.",
        ],
        "references": {},
        "tools": ["httpx"],
        "raw_source": [source_name],
        "manual_verified": False,
        "duplicate_group": safe_str(item.get("url")),
        "notes": None,
    }


def finding_server_banner(item: Dict[str, Any], idx: int, source_name: str) -> Dict[str, Any] | None:
    headers = item.get("header") if isinstance(item.get("header"), dict) else {}
    server = safe_str(item.get("webserver")) or safe_str(headers.get("server"))
    url = safe_str(item.get("url"))
    if not server or not url:
        return None

    return {
        "id": f"WEB-{idx:03d}",
        "title": "서버 배너 정보 노출",
        "category": "정보노출",
        "severity": "info",
        "confidence": "high",
        "status": "needs_review",
        "asset": url,
        "host": safe_str(item.get("host")),
        "url": url,
        "method": "GET",
        "parameter": None,
        "port": safe_int(item.get("port")),
        "description": "응답 헤더 또는 프로브 결과에서 웹 서버 식별 정보가 노출되었습니다.",
        "impact": "직접적인 취약점은 아니지만 공격자가 서버 종류와 버전을 추정하는 데 활용할 수 있습니다.",
        "severity_reason": [
            f"server banner: {server}",
        ],
        "evidence": [
            {"type": "text", "content": f"url: {url}", "path": None},
            {"type": "text", "content": f"server: {server}", "path": None},
        ],
        "reproduction_steps": [
            f"curl -I {url} 명령으로 응답 헤더를 확인합니다.",
            "Server 헤더 또는 유사한 식별 정보 노출 여부를 검증합니다.",
        ],
        "recommendation": [
            "불필요한 서버 배너와 상세 버전 정보 노출을 최소화합니다.",
            "프록시 또는 웹 서버 설정에서 헤더 마스킹을 검토합니다.",
        ],
        "references": {},
        "tools": ["httpx"],
        "raw_source": [source_name],
        "manual_verified": False,
        "duplicate_group": f"banner::{url}",
        "notes": None,
    }


def build_report(findings: List[Dict[str, Any]], target: str, author: str | None) -> Dict[str, Any]:
    return {
        "report_meta": make_report_meta(
            target,
            author,
            ["웹 서비스 프로브", "웹 애플리케이션", "자동 진단 결과"],
        ),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="httpx JSONL 결과를 공통 report JSON으로 변환합니다.")
    parser.add_argument("--input", required=True, help="httpx JSONL 파일 경로")
    parser.add_argument("--output", required=True, help="출력 JSON 파일 경로")
    parser.add_argument("--target", required=True, help="대상 URL 또는 시스템 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    parser.add_argument("--include-banner", action="store_true", help="서버 배너 노출 항목도 포함")
    args = parser.parse_args()

    # 입력 가정:
    # - httpx의 `-jsonl` 출력 형식을 기대합니다.
    # - 각 줄은 JSON 객체이며 `url`, `status_code`, `title`, `webserver`, `header`가 없을 수 있습니다.
    findings: List[Dict[str, Any]] = []
    idx = 1
    for item in load_jsonl(Path(args.input)):
        admin_finding = finding_admin_path(item, idx, Path(args.input).name)
        if admin_finding:
            findings.append(admin_finding)
            idx += 1
        if args.include_banner:
            banner_finding = finding_server_banner(item, idx, Path(args.input).name)
            if banner_finding:
                findings.append(banner_finding)
                idx += 1

    report = build_report(findings, args.target, args.author)
    write_report(Path(args.output), report)
    print(f"[+] httpx 파싱 완료: {args.output}")


if __name__ == "__main__":
    main()
