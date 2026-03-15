from __future__ import annotations

from datetime import date, datetime
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any


def to_plain_data(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if is_dataclass(value):
        return {key: to_plain_data(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: to_plain_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_plain_data(item) for item in value]
    return value


@dataclass(slots=True)
class ArtifactRef:
    kind: str
    raw_path: str | None = None
    redacted_path: str | None = None
    inline: str | None = None


@dataclass(slots=True)
class EvidenceItem:
    type: str
    summary: str
    artifact: ArtifactRef | None = None
    highlights: list[str] = field(default_factory=list)
    extracted_results: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    artifact_links: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssetRef:
    url: str | None
    host: str | None
    path: str | None
    normalized_path: str | None
    method: str | None
    query_keys: list[str] = field(default_factory=list)
    port: int | None = None
    scheme: str | None = None


@dataclass(slots=True)
class Classification:
    weakness_family: str | None = None
    primary_cwe: str | None = None
    related_cwes: list[str] = field(default_factory=list)
    owasp_top10_2025: list[str] = field(default_factory=list)
    kisa_categories: list[str] = field(default_factory=list)
    parameter_or_sink: str | None = None
    matched_rule_id: str | None = None


@dataclass(slots=True)
class SeverityInfo:
    raw: str | None = None
    score: float = 0.0
    level: str = "Info"
    rationale: list[str] = field(default_factory=list)
    overridden: bool = False


@dataclass(slots=True)
class ConfidenceInfo:
    raw: str | None = None
    score: float = 0.0
    level: str = "Low"
    rationale: list[str] = field(default_factory=list)
    analyst_override: float | None = None
    overridden: bool = False


@dataclass(slots=True)
class DedupInfo:
    exact_fingerprint: str
    cluster_fingerprint: str
    cluster_key: str | None = None
    duplicate_of: str | None = None
    is_duplicate: bool = False
    false_positive: bool = False


@dataclass(slots=True)
class ParsedFinding:
    source: str
    source_file: str
    parser: str
    raw_id: str
    kind: str
    title: str
    description: str
    asset: AssetRef
    raw_severity: str | None = None
    raw_confidence: str | None = None
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceItem] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    status: str = "new"


@dataclass(slots=True)
class NormalizedFinding:
    schema_version: str
    run_id: str
    finding_id: str
    source: str
    asset: AssetRef
    classification: Classification
    severity: SeverityInfo
    confidence: ConfidenceInfo
    dedup: DedupInfo
    title: str
    description: str
    evidence: list[EvidenceItem]
    remediation: list[str]
    status: str
    tags: list[str]
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    analyst: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IssueCluster:
    issue_id: str
    cluster_key: str
    title: str
    weakness_family: str | None
    affected_assets: list[str]
    instances: list[str]
    primary_cwe: str | None
    related_cwes: list[str]
    severity: SeverityInfo
    confidence: ConfidenceInfo
    evidence_summary: list[str]
    remediation: list[str]
    references: list[str]
    classification: Classification
    false_positive: bool = False
    suppressed: bool = False
    suppression_status: str | None = None
    suppression_note: str | None = None
    analyst_note: str | None = None
    recommended_owner: str | None = None
    target_due: str | None = None
    affected_instance_count: int = 0


@dataclass(slots=True)
class ReportBundle:
    schema_version: str
    run_id: str
    generated_at: str
    input_files: list[str]
    findings: list[NormalizedFinding]
    issues: list[IssueCluster]
    observations: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    false_positive_findings: list[NormalizedFinding] = field(default_factory=list)
    false_positive_issues: list[IssueCluster] = field(default_factory=list)
    suppressed_issues: list[IssueCluster] = field(default_factory=list)
    override_summary: dict[str, Any] = field(default_factory=dict)
    suppression_summary: dict[str, Any] = field(default_factory=dict)
    comparison_summary: dict[str, Any] = field(default_factory=dict)
    qa_metrics: dict[str, Any] = field(default_factory=dict)
    report_profile: str = "internal"
    report_template: str = "default_internal"
    document_meta: dict[str, Any] = field(default_factory=dict)
