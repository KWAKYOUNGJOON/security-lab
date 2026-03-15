#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from common import load_mapping, make_report_meta, safe_int, safe_str, truncate_text, write_report
from severity_engine import map_burp_severity


def safe_text(element: ET.Element, tag: str, default: str | None = None) -> str | None:
    node = element.find(tag)
    if node is None or node.text is None:
        return default
    return safe_str(node.text, default)


def burp_confidence(value: str | None) -> str:
    mapping = {
        "certain": "high",
        "firm": "high",
        "tentative": "medium",
    }
    return mapping.get((value or "").lower(), "medium")


def parse_issue(issue: ET.Element, index: int, mapping: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    issue_name = safe_text(issue, "name", f"Burp Issue {index}") or f"Burp Issue {index}"
    mapped = (mapping.get("burp_issue_names") or {}).get(issue_name, {})

    location = safe_text(issue, "location")
    host = safe_text(issue, "host")
    path = safe_text(issue, "path")
    severity = map_burp_severity(safe_text(issue, "severity"))
    confidence = burp_confidence(safe_text(issue, "confidence"))
    port = safe_int(issue.get("port"))

    evidence = []
    request_response_nodes = issue.findall("requestresponse")
    if request_response_nodes:
        req = request_response_nodes[0].find("request")
        res = request_response_nodes[0].find("response")
        if req is not None and safe_str(req.text):
            evidence.append({"type": "http_request", "content": truncate_text(req.text), "path": None})
        if res is not None and safe_str(res.text):
            evidence.append({"type": "http_response", "content": truncate_text(res.text), "path": None})
    if location:
        evidence.append({"type": "text", "content": f"location: {location}", "path": None})

    refs: Dict[str, List[str]] = {}
    if mapped.get("owasp"):
        refs["owasp"] = list(mapped["owasp"])
    if mapped.get("kisa"):
        refs["kisa"] = list(mapped["kisa"])

    remediation = safe_text(issue, "remediationBackground", "관련 보안 설정과 입력 검증 정책을 검토해야 합니다.") or ""
    description = safe_text(issue, "issueBackground", "Burp에서 보안 이슈가 탐지되었습니다.") or ""

    return {
        "id": f"WEB-{index:03d}",
        "title": safe_str(mapped.get("title_ko")) or issue_name,
        "category": safe_str(mapped.get("category"), "자동진단") or "자동진단",
        "severity": severity,
        "confidence": confidence,
        "status": "needs_review",
        "asset": host or location or "unknown",
        "host": host,
        "url": location,
        "method": None,
        "parameter": None,
        "port": port,
        "description": description,
        "impact": "애플리케이션 구현 또는 설정 문제로 인해 정보 노출이나 보안 통제 우회 위험이 존재할 수 있습니다.",
        "severity_reason": [
            f"burp severity: {severity}",
            f"burp confidence: {confidence}",
        ],
        "evidence": evidence,
        "reproduction_steps": [
            "Burp 원본 이슈의 위치와 요청/응답을 확인합니다.",
            "동일한 요청을 Repeater 등으로 재전송해 결과가 반복되는지 검증합니다.",
        ],
        "recommendation": [
            remediation,
            "영향 범위와 악용 가능성을 수동 검증해 최종 위험도를 확정합니다.",
        ],
        "references": refs,
        "tools": ["burp"],
        "raw_source": [source_name],
        "manual_verified": False,
        "duplicate_group": issue_name,
        "notes": path,
    }


def build_report(findings: List[Dict[str, Any]], target: str, author: str | None) -> Dict[str, Any]:
    return {
        "report_meta": make_report_meta(
            target,
            author,
            ["웹 애플리케이션", "웹 서버 설정", "Burp 점검 결과"],
        ),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Burp XML 결과를 공통 report JSON으로 변환합니다.")
    parser.add_argument("--input", required=True, help="Burp XML 파일 경로")
    parser.add_argument("--output", required=True, help="출력 JSON 파일 경로")
    parser.add_argument("--target", required=True, help="대상 URL 또는 시스템 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    parser.add_argument("--mapping", default=None, help="매핑 JSON 파일 경로")
    args = parser.parse_args()

    # 입력 가정:
    # - Burp Scanner의 issue export XML 형식을 기대합니다.
    # - 루트 아래 `issue` 노드가 반복되며 request/response는 없을 수도 있습니다.
    mapping = load_mapping(Path(args.mapping)) if args.mapping else {}
    try:
        tree = ET.parse(args.input)
    except ET.ParseError as exc:
        raise SystemExit(f"Burp XML 파싱 실패: {exc}") from exc

    root = tree.getroot()
    findings = [parse_issue(issue, idx, mapping, Path(args.input).name) for idx, issue in enumerate(root.findall("issue"), start=1)]
    report = build_report(findings, args.target, args.author)
    write_report(Path(args.output), report)
    print(f"[+] Burp 파싱 완료: {args.output}")


if __name__ == "__main__":
    main()
