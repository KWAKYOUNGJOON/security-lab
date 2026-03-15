#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from common import load_jsonl, load_mapping, make_report_meta, safe_str, truncate_text, write_report
from severity_engine import map_nuclei_severity


def to_category(value: Any) -> str:
    if isinstance(value, list):
        joined = ", ".join(safe_str(item, "") for item in value if safe_str(item, ""))
        return joined or "자동진단"
    return safe_str(value, "자동진단") or "자동진단"


def to_finding(item: Dict[str, Any], index: int, mapping: Dict[str, Any]) -> Dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    template_id = safe_str(item.get("template-id"), f"template-{index}") or f"template-{index}"
    mapped = (mapping.get("nuclei_templates") or {}).get(template_id, {})

    title = safe_str(mapped.get("title_ko")) or safe_str(info.get("name")) or template_id
    category = safe_str(mapped.get("category")) or to_category(info.get("tags"))
    severity = map_nuclei_severity(safe_str(info.get("severity")))
    matched_at = safe_str(item.get("matched-at")) or safe_str(item.get("url")) or safe_str(item.get("host"))
    host = safe_str(item.get("host"))

    evidence = []
    if matched_at:
        evidence.append({"type": "text", "content": f"matched-at: {matched_at}", "path": None})
    if safe_str(item.get("matcher-name")):
        evidence.append({"type": "text", "content": f"matcher-name: {item.get('matcher-name')}", "path": None})
    if safe_str(item.get("request")):
        evidence.append({"type": "http_request", "content": truncate_text(item.get("request")), "path": None})
    if safe_str(item.get("response")):
        evidence.append({"type": "http_response", "content": truncate_text(item.get("response")), "path": None})

    refs: Dict[str, List[str]] = {}
    if mapped.get("owasp"):
        refs["owasp"] = list(mapped["owasp"])
    if mapped.get("kisa"):
        refs["kisa"] = list(mapped["kisa"])

    return {
        "id": f"WEB-{index:03d}",
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "medium",
        "status": "needs_review",
        "asset": host or matched_at or "unknown",
        "host": host,
        "url": matched_at,
        "method": None,
        "parameter": None,
        "port": None,
        "description": safe_str(info.get("description"), f"Nuclei 템플릿 `{template_id}` 결과가 탐지되었습니다.") or "",
        "impact": "자동 진단 결과이므로 실제 영향도와 악용 가능성은 수동 검증으로 확정해야 합니다.",
        "severity_reason": [
            f"nuclei severity: {severity}",
            f"template-id: {template_id}",
        ],
        "evidence": evidence,
        "reproduction_steps": [
            "원본 nuclei 결과에서 탐지 URL과 matcher 이름을 확인합니다.",
            "동일한 요청을 재현해 응답이 반복되는지 수동 검증합니다.",
        ],
        "recommendation": [
            "탐지된 항목이 실제 노출인지 먼저 수동으로 확인합니다.",
            "불필요한 엔드포인트, 설정, 노출 정보를 제거하거나 접근을 제한합니다.",
            "관련 서버와 애플리케이션을 최신 보안 설정 기준에 맞게 점검합니다.",
        ],
        "references": refs,
        "tools": ["nuclei"],
        "raw_source": [value for value in [safe_str(item.get("template-path"))] if value],
        "manual_verified": False,
        "duplicate_group": template_id,
        "notes": None,
    }


def build_report(findings: List[Dict[str, Any]], target: str, author: str | None) -> Dict[str, Any]:
    return {
        "report_meta": make_report_meta(
            target,
            author,
            ["웹 애플리케이션", "웹 서버 설정", "자동 진단 결과"],
        ),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="nuclei JSONL 결과를 공통 report JSON으로 변환합니다.")
    parser.add_argument("--input", required=True, help="nuclei JSONL 파일 경로")
    parser.add_argument("--output", required=True, help="출력 JSON 파일 경로")
    parser.add_argument("--target", required=True, help="대상 URL 또는 시스템 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    parser.add_argument("--mapping", default=None, help="매핑 JSON 파일 경로")
    args = parser.parse_args()

    # 입력 가정:
    # - nuclei의 `-jsonl` 출력 형식을 기대합니다.
    # - 각 줄은 JSON 객체이며 `info`, `template-id`, `host` 계열 필드가 부분적으로 누락될 수 있습니다.
    mapping = load_mapping(Path(args.mapping)) if args.mapping else {}
    findings = [to_finding(item, idx, mapping) for idx, item in enumerate(load_jsonl(Path(args.input)), start=1)]
    report = build_report(findings, args.target, args.author)
    write_report(Path(args.output), report)
    print(f"[+] nuclei 파싱 완료: {args.output}")


if __name__ == "__main__":
    main()
