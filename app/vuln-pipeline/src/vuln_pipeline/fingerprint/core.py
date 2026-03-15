from __future__ import annotations

from vuln_pipeline.models import NormalizedFinding


def build_cluster_key(finding: NormalizedFinding) -> str:
    parts = [
        finding.classification.weakness_family or "unknown",
        finding.asset.host or "unknown-host",
        finding.asset.normalized_path or "unknown-path",
        finding.classification.parameter_or_sink or "none",
        finding.classification.primary_cwe or "unknown-cwe",
    ]
    return "|".join(parts)

