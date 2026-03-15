#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from common import load_json, make_report_meta, safe_int, safe_str, write_report
from severity_engine import classify_nikto_message


def normalize_hosts(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("hosts"), list):
            return [item for item in data["hosts"] if isinstance(item, dict)]
        if data.get("host") and isinstance(data.get("vulnerabilities"), list):
            return [data]
    return []


def to_findings(host_obj: Dict[str, Any], start_index: int, source_name: str) -> List[Dict[str, Any]]:
    findings = []
    host = safe_str(host_obj.get("host"))
    port = safe_int(host_obj.get("port"))
    vulnerabilities = host_obj.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return findings

    for offset, vuln in enumerate(vulnerabilities, start=0):
        if not isinstance(vuln, dict):
            continue
        url_path = safe_str(vuln.get("url"), "/") or "/"
        message = safe_str(vuln.get("msg"), "Nikto 결과") or "Nikto 결과"
        title, category, severity = classify_nikto_message(message, url_path)
        full_url = f"https://{host}{url_path}" if host else url_path

        findings.append(
            {
                "id": f"WEB-{start_index + offset:03d}",
                "title": title,
                "category": category,
                "severity": severity,
                "confidence": "medium",
                "status": "needs_review",
                "asset": full_url,
                "host": host,
                "url": full_url,
                "method": safe_str(vuln.get("method")),
                "parameter": None,
                "port": port,
                "description": message,
                "impact": "Nikto 결과는 웹 서버 또는 애플리케이션 구성에 대해 추가 보안 검토가 필요함을 의미합니다.",
                "severity_reason": [
                    f"nikto id: {safe_str(vuln.get('id'), '-')}",
                    "Nikto JSON 결과 기반",
                ],
                "evidence": [
                    {"type": "text", "content": f"url: {url_path}", "path": None},
                    {"type": "text", "content": f"message: {message}", "path": None},
                    {"type": "text", "content": f"references: {safe_str(vuln.get('references'), '-')}", "path": None},
                ],
                "reproduction_steps": [
                    f"{safe_str(vuln.get('method'), 'GET')} 요청으로 {url_path} 경로를 확인합니다.",
                    "동일한 메시지 또는 관련 설정 상태가 재현되는지 검증합니다.",
                ],
                "recommendation": [
                    "탐지된 설정 또는 노출 항목이 실제 위험인지 수동 검증합니다.",
                    "불필요한 테스트 페이지, 진단 페이지, 민감 파일은 제거하거나 접근을 제한합니다.",
                    "권장 보안 헤더와 최신 서버 구성을 적용합니다.",
                ],
                "references": {},
                "tools": ["nikto"],
                "raw_source": [source_name],
                "manual_verified": False,
                "duplicate_group": f"{host}:{url_path}:{title}",
                "notes": safe_str(host_obj.get("banner")),
            }
        )

    return findings


def build_report(findings: List[Dict[str, Any]], target: str, author: str | None) -> Dict[str, Any]:
    return {
        "report_meta": make_report_meta(
            target,
            author,
            ["웹 서버 점검", "웹 애플리케이션", "자동 진단 결과"],
        ),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Nikto JSON 결과를 공통 report JSON으로 변환합니다.")
    parser.add_argument("--input", required=True, help="Nikto JSON 파일 경로")
    parser.add_argument("--output", required=True, help="출력 JSON 파일 경로")
    parser.add_argument("--target", required=True, help="대상 URL 또는 시스템 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    args = parser.parse_args()

    # 입력 가정:
    # - Nikto JSON 또는 이를 가공한 JSON에서 `hosts[]` 또는 `host + vulnerabilities[]` 형태를 기대합니다.
    # - 각 취약점 항목의 `msg`, `url`, `method`는 누락될 수 있으므로 기본값을 사용합니다.
    data = load_json(Path(args.input))
    hosts = normalize_hosts(data)

    findings: List[Dict[str, Any]] = []
    idx = 1
    for host_obj in hosts:
        partial = to_findings(host_obj, idx, Path(args.input).name)
        findings.extend(partial)
        idx += len(partial)

    report = build_report(findings, args.target, args.author)
    write_report(Path(args.output), report)
    print(f"[+] Nikto 파싱 완료: {args.output}")


if __name__ == "__main__":
    main()
