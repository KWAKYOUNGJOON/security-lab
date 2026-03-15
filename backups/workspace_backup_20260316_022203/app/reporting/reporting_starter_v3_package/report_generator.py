#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

try:
    from jsonschema import validate
except ImportError:
    validate = None

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError as exc:
    raise SystemExit("jinja2가 필요합니다. 먼저 `pip install -r requirements.txt`를 실행하세요.") from exc

from parsers.common import load_json

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def build_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    findings = data.get("findings", [])
    counts = Counter((finding.get("severity") or "info").lower() for finding in findings)
    return {
        "total_findings": len(findings),
        "by_severity": {severity: counts.get(severity, 0) for severity in SEVERITIES},
    }


def normalize(data: Dict[str, Any]) -> Dict[str, Any]:
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError("입력 JSON의 `findings`는 배열이어야 합니다.")

    for finding in findings:
        finding["severity"] = (finding.get("severity") or "info").lower()
        finding["confidence"] = (finding.get("confidence") or "medium").lower()
        finding["status"] = finding.get("status") or "needs_review"
        finding.setdefault("host", None)
        finding.setdefault("url", None)
        finding.setdefault("method", None)
        finding.setdefault("parameter", None)
        finding.setdefault("port", None)
        finding.setdefault("severity_reason", [])
        finding.setdefault("evidence", [])
        finding.setdefault("references", {})
        finding.setdefault("raw_source", [])
        finding.setdefault("notes", None)
        finding.setdefault("duplicate_group", None)
        finding.setdefault("manual_verified", False)

    data["summary"] = build_summary(data)
    return data


def validate_json(data: Dict[str, Any], schema_path: Path) -> None:
    if validate is None:
        print("[!] jsonschema가 설치되지 않아 스키마 검증을 건너뜁니다.")
        return
    schema = load_json(schema_path)
    payload = deepcopy(data)
    payload.pop("summary", None)
    validate(instance=payload, schema=schema)


def build_render_context(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "report_meta": data["report_meta"],
        "findings": data["findings"],
        "summary": data["summary"],
    }


def render_template(template_dir: Path, template_name: str, context: Dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    return template.render(**context)


def main() -> None:
    parser = argparse.ArgumentParser(description="취약점 진단 Markdown 보고서를 생성합니다.")
    parser.add_argument("--input", required=True, help="정규화된 findings JSON 경로")
    parser.add_argument("--schema", required=True, help="JSON Schema 경로")
    parser.add_argument("--template-dir", required=True, help="Jinja2 템플릿 디렉터리")
    parser.add_argument("--template", default="report.md.j2", help="템플릿 파일명")
    parser.add_argument("--output", required=True, help="출력 Markdown 파일 경로")
    parser.add_argument("--skip-validation", action="store_true", help="스키마 검증 생략")
    args = parser.parse_args()

    data = normalize(load_json(Path(args.input)))

    if not args.skip_validation:
        validate_json(data, Path(args.schema))

    rendered = render_template(Path(args.template_dir), args.template, build_render_context(data))
    Path(args.output).write_text(rendered, encoding="utf-8")
    print(f"[+] 보고서 생성 완료: {args.output}")


if __name__ == "__main__":
    main()
