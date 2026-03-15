from __future__ import annotations

from collections import defaultdict

from vuln_pipeline.models import NormalizedFinding, ParsedFinding


def enrich_findings(findings: list[NormalizedFinding], observations: list[ParsedFinding]) -> tuple[list[NormalizedFinding], list[dict]]:
    indexed: dict[str, list[ParsedFinding]] = defaultdict(list)
    observation_rows: list[dict] = []
    for observation in observations:
        host = observation.asset.host or observation.asset.url or "unknown"
        indexed[host.lower()].append(observation)
        observation_rows.append(
            {
                "host": host,
                "title": observation.title,
                "status_code": observation.metadata.get("status_code"),
                "tech": observation.tags,
                "webserver": observation.metadata.get("webserver"),
            }
        )

    for finding in findings:
        host = finding.asset.host or ""
        if host.lower() in indexed:
            notes = []
            for item in indexed[host.lower()][:3]:
                tech = ",".join(item.tags) if item.tags else "n/a"
                notes.append(f"httpx status={item.metadata.get('status_code')} tech={tech}")
            if notes:
                finding.raw.setdefault("enrichment", {})
                finding.raw["enrichment"]["httpx"] = notes
    return findings, observation_rows
