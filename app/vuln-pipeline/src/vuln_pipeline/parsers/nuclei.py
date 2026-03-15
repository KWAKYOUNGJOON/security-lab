from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from vuln_pipeline.evidence import save_artifact_pair
from vuln_pipeline.models import AssetRef, EvidenceItem, ParsedFinding
from vuln_pipeline.parsers.common import read_jsonl
from vuln_pipeline.utils import safe_slug


def parse_nuclei_jsonl(path: Path, artifact_root: Path, warnings: list[dict[str, str]] | None = None) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    parser_warnings: list[dict[str, str]] = warnings if warnings is not None else []
    allowed_severity = {"critical", "high", "medium", "low", "info"}
    for index, item in enumerate(read_jsonl(path, parser_warnings), start=1):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        title = info.get("name") or item.get("template-id") or f"nuclei-{index}"
        severity_value = str(info.get("severity")) if info.get("severity") else None
        if severity_value and severity_value.lower() not in allowed_severity:
            parser_warnings.append(
                {"type": "unknown_severity", "file": str(path), "value": severity_value, "template": str(item.get("template-id") or title)}
            )
        if not item.get("matched-at") and not item.get("url") and not item.get("host"):
            parser_warnings.append({"type": "missing_field", "file": str(path), "field": "matched-at/url/host", "template": str(title)})
        stem = f"nuclei_{index:03d}_{safe_slug(title)}"
        evidence: list[EvidenceItem] = []
        request_text = item.get("request")
        response_text = item.get("response")
        if isinstance(request_text, str):
            artifact = save_artifact_pair(artifact_root / "nuclei", stem, "request", request_text)
            if artifact:
                evidence.append(
                    EvidenceItem(
                        type="request",
                        summary="Nuclei request captured in result output.",
                        artifact=artifact,
                        artifact_links=[value for value in [artifact.raw_path, artifact.redacted_path] if value],
                    )
                )
        if isinstance(response_text, str):
            artifact = save_artifact_pair(artifact_root / "nuclei", stem, "response", response_text)
            if artifact:
                response_lines = [line for line in response_text.splitlines() if line][:3]
                evidence.append(
                    EvidenceItem(
                        type="response",
                        summary="Nuclei response captured in result output.",
                        artifact=artifact,
                        artifact_links=[value for value in [artifact.raw_path, artifact.redacted_path] if value],
                        highlights=response_lines,
                    )
                )
        matched_at = item.get("matched-at") or item.get("url") or item.get("host")
        parsed_url = urlparse(str(matched_at)) if matched_at and "://" in str(matched_at) else None
        extracted = [str(value) for value in item.get("extracted-results", []) if value]
        if matched_at:
            evidence.append(
                EvidenceItem(
                    type="match",
                    summary=f"Nuclei matched at {matched_at}",
                    extracted_results=extracted,
                    highlights=[str(value) for value in [item.get("matcher-name"), item.get("matcher-status"), *extracted[:2]] if value is not None and value != ""],
                    reproduction_steps=["Replay the saved nuclei request or issue the equivalent HTTP request to confirm the match."],
                )
            )
        findings.append(
            ParsedFinding(
                source="nuclei",
                source_file=str(path),
                parser="nuclei_jsonl",
                raw_id=item.get("template-id") or str(index),
                kind="finding",
                title=str(title),
                description=str(info.get("description") or ""),
                asset=AssetRef(
                    url=str(matched_at) if matched_at else None,
                    host=str(item.get("host")) if item.get("host") else None,
                    path=parsed_url.path if parsed_url else None,
                    normalized_path=parsed_url.path if parsed_url else None,
                    method=None,
                    scheme=str(item.get("scheme")) if item.get("scheme") else None,
                ),
                raw_severity=severity_value,
                raw_confidence=None,
                tags=[str(tag) for tag in info.get("tags", []) if tag],
                references=[str(item.get("template-id"))] if item.get("template-id") else [],
                metadata={
                    "template_id": item.get("template-id"),
                    "template_path": item.get("template-path"),
                    "matcher_name": item.get("matcher-name"),
                    "curl_command": item.get("curl-command"),
                    "extracted_results": extracted,
                    "response_highlights": [value for value in extracted[:3]],
                },
                evidence=evidence,
                remediation=[],
                status="needs_review",
            )
        )
    return findings
