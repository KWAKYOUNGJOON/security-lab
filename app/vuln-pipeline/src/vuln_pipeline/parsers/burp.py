from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from vuln_pipeline.evidence import save_artifact_pair
from vuln_pipeline.models import AssetRef, EvidenceItem, ParsedFinding
from vuln_pipeline.parsers.common import decode_maybe_base64
from vuln_pipeline.utils import safe_slug


def _text(node: ET.Element, tag: str) -> str | None:
    child = node.find(tag)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def parse_burp_xml(path: Path, artifact_root: Path, warnings: list[dict[str, str]] | None = None) -> list[ParsedFinding]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        if warnings is not None:
            warnings.append({"type": "malformed_xml", "file": str(path), "error": str(exc)})
        return []
    findings: list[ParsedFinding] = []
    for index, issue in enumerate(root.findall("issue"), start=1):
        host = _text(issue, "host")
        url = _text(issue, "path") or _text(issue, "location")
        parsed_url = urlparse(url) if url else None
        issue_name = _text(issue, "name") or f"burp-issue-{index}"
        if not _text(issue, "severity") and warnings is not None:
            warnings.append({"type": "missing_field", "file": str(path), "field": "severity", "issue": issue_name})
        request_response = issue.find("requestresponse")
        evidence: list[EvidenceItem] = []
        if request_response is not None:
            stem = f"burp_{index:03d}_{safe_slug(issue_name)}"
            request_node = request_response.find("request")
            response_node = request_response.find("response")
            if request_node is not None:
                request_text = decode_maybe_base64(request_node.text, request_node.attrib.get("base64") == "true")
                artifact = save_artifact_pair(artifact_root / "burp", stem, "request", request_text)
                if artifact:
                    evidence.append(
                        EvidenceItem(
                            type="request",
                            summary="Captured HTTP request from Burp issue export.",
                            artifact=artifact,
                            artifact_links=[value for value in [artifact.raw_path, artifact.redacted_path] if value],
                            reproduction_steps=["Replay the saved request artifact against the same endpoint."],
                        )
                    )
            if response_node is not None:
                response_text = decode_maybe_base64(response_node.text, response_node.attrib.get("base64") == "true")
                artifact = save_artifact_pair(artifact_root / "burp", stem, "response", response_text)
                if artifact:
                    evidence.append(
                        EvidenceItem(
                            type="response",
                            summary="Captured HTTP response from Burp issue export.",
                            artifact=artifact,
                            artifact_links=[value for value in [artifact.raw_path, artifact.redacted_path] if value],
                            highlights=[response_text.splitlines()[0]] if response_text else [],
                        )
                    )
        issue_background = _text(issue, "issueBackground")
        remediation_background = _text(issue, "remediationBackground")
        remediation_detail = _text(issue, "remediationDetail")
        issue_detail = _text(issue, "issueDetail") or issue_background or ""
        response_variations = [
            _text(variation, "description") or "".join((variation.itertext())).strip()
            for variation in issue.findall("variations/variation")
            if "".join(variation.itertext()).strip()
        ]
        if issue_background:
            evidence.append(EvidenceItem(type="background", summary="Burp issue background preserved.", highlights=[issue_background[:240]]))
        if response_variations:
            evidence.append(EvidenceItem(type="variation", summary="Burp variations preserved.", highlights=response_variations[:3]))
        findings.append(
            ParsedFinding(
                source="burp",
                source_file=str(path),
                parser="burp_xml",
                raw_id=str(index),
                kind="finding",
                title=issue_name,
                description=issue_detail,
                asset=AssetRef(
                    url=url,
                    host=host,
                    path=parsed_url.path if parsed_url else _text(issue, "path"),
                    normalized_path=parsed_url.path if parsed_url else _text(issue, "path"),
                    method=None,
                    port=int(issue.attrib["port"]) if issue.attrib.get("port", "").isdigit() else None,
                    scheme=issue.attrib.get("protocol"),
                ),
                raw_severity=_text(issue, "severity"),
                raw_confidence=_text(issue, "confidence"),
                tags=[],
                references=[],
                metadata={
                    "serial_number": _text(issue, "serialNumber"),
                    "type_index": _text(issue, "typeIndex"),
                    "location": _text(issue, "location"),
                    "issue_background": issue_background,
                    "issue_detail": issue_detail,
                    "variations": response_variations,
                },
                evidence=evidence,
                remediation=[value for value in [remediation_background, remediation_detail] if value],
                status="needs_review",
            )
        )
    if not findings and warnings is not None:
        warnings.append({"type": "empty_file", "file": str(path), "error": "No Burp issues found."})
    return findings
