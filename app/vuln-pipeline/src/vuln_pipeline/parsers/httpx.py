from __future__ import annotations

from pathlib import Path

from vuln_pipeline.models import AssetRef, ParsedFinding
from vuln_pipeline.parsers.common import read_jsonl


def parse_httpx_jsonl(path: Path, warnings: list[dict[str, str]] | None = None) -> list[ParsedFinding]:
    observations: list[ParsedFinding] = []
    parser_warnings: list[dict[str, str]] = warnings if warnings is not None else []
    for index, item in enumerate(read_jsonl(path, parser_warnings), start=1):
        headers = item.get("header") if isinstance(item.get("header"), dict) else {}
        title = item.get("title") or "HTTP service observation"
        if not item.get("url") and not item.get("input"):
            parser_warnings.append({"type": "missing_field", "file": str(path), "field": "url/input", "record": str(index)})
        description = f"Observed {item.get('url') or item.get('input')} status={item.get('status-code')} tech={','.join(item.get('tech', [])) if isinstance(item.get('tech'), list) else ''}".strip()
        observations.append(
            ParsedFinding(
                source="httpx",
                source_file=str(path),
                parser="httpx_jsonl",
                raw_id=str(index),
                kind="observation",
                title=str(title),
                description=description,
                asset=AssetRef(
                    url=str(item.get("url")) if item.get("url") else None,
                    host=str(item.get("host")) if item.get("host") else str(item.get("input")) if item.get("input") else None,
                    path=None,
                    normalized_path=None,
                    method="GET",
                    port=int(item["port"]) if isinstance(item.get("port"), int) else None,
                    scheme=str(item.get("scheme")) if item.get("scheme") else None,
                ),
                raw_severity=None,
                raw_confidence=None,
                tags=[str(value) for value in item.get("tech", []) if value] if isinstance(item.get("tech"), list) else [],
                references=[],
                metadata={
                    "status_code": item.get("status-code"),
                    "webserver": item.get("webserver"),
                    "content_type": item.get("content-type") or headers.get("content-type"),
                    "headers": headers,
                },
                evidence=[],
                remediation=[],
                status="observed",
            )
        )
    if not observations and warnings is not None:
        warnings.append({"type": "empty_file", "file": str(path), "error": "No httpx observations found."})
    return observations
