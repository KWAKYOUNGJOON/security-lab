from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from vuln_pipeline.models import AssetRef, Classification, ConfidenceInfo, DedupInfo, NormalizedFinding, ParsedFinding, SeverityInfo
from vuln_pipeline.utils import stable_hash

UUID_PATTERN = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE)
HEX_PATTERN = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
INT_PATTERN = re.compile(r"(?<=/)\d{2,}(?=/|$)")
TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")


def normalize_title(value: str) -> str:
    lowered = value.strip().lower()
    lowered = re.sub(r"\s+", " ", lowered)
    lowered = lowered.replace("burp scanner detected ", "")
    return lowered


def normalize_query_keys(url: str | None) -> list[str]:
    if not url:
        return []
    parsed = urlparse(url)
    return sorted({key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})


def normalize_path_pattern(path: str | None) -> str | None:
    if not path:
        return None
    value = path
    value = UUID_PATTERN.sub("{uuid}", value)
    value = HEX_PATTERN.sub("{hex}", value)
    value = TOKEN_PATTERN.sub("{token}", value)
    value = INT_PATTERN.sub("{id}", value)
    return value


def build_asset(asset: AssetRef) -> AssetRef:
    url = asset.url
    host = asset.host
    path = asset.path
    method = asset.method.upper() if asset.method else "GET"
    if path and "://" in path:
        path = urlparse(path).path
    parsed = urlparse(url) if url else None
    if parsed:
        host = host or parsed.hostname
        path = path or parsed.path
    normalized_path = normalize_path_pattern(path)
    return AssetRef(
        url=url,
        host=host.lower() if host else None,
        path=path,
        normalized_path=normalized_path,
        method=method,
        query_keys=normalize_query_keys(url),
        port=asset.port or (parsed.port if parsed else None),
        scheme=asset.scheme or (parsed.scheme if parsed else None),
    )


def normalize_finding(parsed_finding: ParsedFinding, run_id: str, index: int) -> NormalizedFinding:
    asset = build_asset(parsed_finding.asset)
    title = normalize_title(parsed_finding.title)
    exact_fingerprint = stable_hash(
        parsed_finding.source,
        title,
        asset.host,
        asset.normalized_path,
        parsed_finding.raw_severity,
    )
    cluster_fingerprint = stable_hash(title, asset.host, asset.normalized_path)
    return NormalizedFinding(
        schema_version="1.0",
        run_id=run_id,
        finding_id=f"F-{index:04d}",
        source=parsed_finding.source,
        asset=asset,
        classification=Classification(),
        severity=SeverityInfo(raw=parsed_finding.raw_severity),
        confidence=ConfidenceInfo(raw=parsed_finding.raw_confidence),
        dedup=DedupInfo(exact_fingerprint=exact_fingerprint, cluster_fingerprint=cluster_fingerprint),
        title=title,
        description=parsed_finding.description,
        evidence=parsed_finding.evidence,
        remediation=parsed_finding.remediation,
        status=parsed_finding.status,
        tags=sorted({tag.lower() for tag in parsed_finding.tags}),
        references=parsed_finding.references,
        raw={
            "raw_id": parsed_finding.raw_id,
            "kind": parsed_finding.kind,
            "metadata": parsed_finding.metadata,
            "raw_title": parsed_finding.title,
            "source_file": parsed_finding.source_file,
        },
    )
