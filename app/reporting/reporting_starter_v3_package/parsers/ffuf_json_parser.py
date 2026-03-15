#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict, List

from common import load_json, make_report_meta, safe_int, safe_str, write_report
from severity_engine import classify_ffuf_result


def safe_b64decode(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
        text = decoded.decode("utf-8", errors="ignore")
        if text and all(char.isprintable() or char in "\t\r\n" for char in text):
            return text
    except Exception:
        pass
    return value


def to_finding(item: Dict[str, Any], index: int, source_name: str) -> Dict[str, Any]:
    url = safe_str(item.get("url"), "unknown") or "unknown"
    status = safe_int(item.get("status")) or 0
    title, category, severity = classify_ffuf_result(url, status)

    decoded_input = {}
    raw_input = item.get("input") if isinstance(item.get("input"), dict) else {}
    for key, value in raw_input.items():
        decoded_input[str(key)] = safe_b64decode(value) if isinstance(value, str) else str(value)

    evidence = [
        {"type": "text", "content": f"url: {url}", "path": None},
        {"type": "text", "content": f"status: {status}", "path": None},
    ]
    size = safe_int(item.get("length"))
    if size is not None:
        evidence.append({"type": "text", "content": f"size: {size} bytes", "path": None})
    if decoded_input:
        evidence.append({"type": "text", "content": f"input: {json.dumps(decoded_input, ensure_ascii=False)}", "path": None})

    return {
        "id": f"WEB-{index:03d}",
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "medium",
        "status": "needs_review",
        "asset": url,
        "host": None,
        "url": url,
        "method": "GET",
        "parameter": None,
        "port": None,
        "description": "ffuf 디렉터리/파일 탐색 결과, 주목할 만한 경로가 응답한 것이 확인되었습니다.",
        "impact": "민감 경로나 파일이 노출된 경우 관리자 인터페이스 접근, 설정 정보 노출, 추가 공격면 탐색 위험이 존재합니다.",
        "severity_reason": [
            f"ffuf status: {status}",
            "유효한 응답으로 판단된 경로",
        ],
        "evidence": evidence,
        "reproduction_steps": [
            f"브라우저 또는 curl로 {url} 경로에 직접 접근합니다.",
            "동일한 상태 코드와 응답 본문이 재현되는지 확인합니다.",
        ],
        "recommendation": [
            "불필요한 민감 경로와 파일은 제거하거나 외부 접근을 차단합니다.",
            "관리자 인터페이스에는 접근통제와 인증 강화를 적용합니다.",
            "운영 중 필요한 경로인지 서비스 담당자와 함께 검토합니다.",
        ],
        "references": {},
        "tools": ["ffuf"],
        "raw_source": [source_name],
        "manual_verified": False,
        "duplicate_group": url,
        "notes": None,
    }


def build_report(findings: List[Dict[str, Any]], target: str, author: str | None) -> Dict[str, Any]:
    return {
        "report_meta": make_report_meta(
            target,
            author,
            ["웹 애플리케이션", "경로 탐색", "자동 진단 결과"],
        ),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="ffuf JSON 결과를 공통 report JSON으로 변환합니다.")
    parser.add_argument("--input", required=True, help="ffuf JSON 파일 경로")
    parser.add_argument("--output", required=True, help="출력 JSON 파일 경로")
    parser.add_argument("--target", required=True, help="대상 URL 또는 시스템 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    args = parser.parse_args()

    # 입력 가정:
    # - ffuf의 `-of json` 출력 형식을 기대합니다.
    # - 루트 `results` 배열 안의 각 항목은 `url`, `status`, `input`을 부분적으로 가질 수 있습니다.
    data = load_json(Path(args.input))
    if not isinstance(data, dict):
        raise SystemExit("ffuf 입력 파일은 JSON 객체여야 합니다.")

    results = data.get("results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise SystemExit("ffuf 입력 파일의 `results`는 배열이어야 합니다.")

    findings = [to_finding(item, idx, Path(args.input).name) for idx, item in enumerate(results, start=1) if isinstance(item, dict)]
    report = build_report(findings, args.target, args.author)
    write_report(Path(args.output), report)
    print(f"[+] ffuf 파싱 완료: {args.output}")


if __name__ == "__main__":
    main()
