from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_pipeline.models import NormalizedFinding


def _severity_level(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def _confidence_level(score: float) -> str:
    if score >= 0.85:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def score_finding(
    finding: NormalizedFinding,
    config_path: Path,
    return_decision: bool = False,
) -> NormalizedFinding | tuple[NormalizedFinding, dict[str, Any]]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    family = finding.classification.weakness_family or "default"
    profile = config["families"].get(family, config["families"]["default"])
    severity_score = _clamp(
        profile["family_base"]
        + profile["exploitability"]
        + profile["impact"]
        + profile["exposure"]
        + profile["business_modifier"],
        0.0,
        10.0,
    )
    rationale = [f"{key}={value}" for key, value in profile.items()]
    if finding.source == "nuclei" and finding.raw.get("metadata", {}).get("extracted_results"):
        severity_score = _clamp(severity_score + 0.3, 0.0, 10.0)
        rationale.append("evidence_bonus=0.3")
    finding.severity.score = round(severity_score, 1)
    finding.severity.level = _severity_level(severity_score)
    finding.severity.rationale = rationale

    confidence_score = config["confidence"]["defaults"].get(finding.source, 0.35)
    confidence_rationale = [f"source_default={confidence_score}"]
    if finding.source == "burp":
        burp_map = config["confidence"]["burp"]
        raw = (finding.confidence.raw or "").lower()
        confidence_score = burp_map.get(raw, confidence_score)
        confidence_rationale.append(f"burp_raw={raw}")
    elif finding.source == "nuclei":
        if finding.raw.get("metadata", {}).get("extracted_results"):
            confidence_score += 0.15
            confidence_rationale.append("extracted_results_bonus=0.15")
        if any(item.artifact for item in finding.evidence):
            confidence_score += 0.10
            confidence_rationale.append("artifact_bonus=0.10")
    elif finding.source == "httpx":
        confidence_rationale.append("observation_only")
    if finding.confidence.analyst_override is not None:
        confidence_score = finding.confidence.analyst_override
        confidence_rationale.append("analyst_override")
    confidence_score = _clamp(confidence_score, 0.0, 1.0)
    finding.confidence.score = round(confidence_score, 2)
    finding.confidence.level = _confidence_level(confidence_score)
    finding.confidence.rationale = confidence_rationale
    decision = {
        "finding_id": finding.finding_id,
        "family": family,
        "severity_score": finding.severity.score,
        "severity_level": finding.severity.level,
        "severity_rationale": finding.severity.rationale,
        "confidence_score": finding.confidence.score,
        "confidence_level": finding.confidence.level,
        "confidence_rationale": finding.confidence.rationale,
    }
    return (finding, decision) if return_decision else finding
