from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class KnowledgePack:
    def __init__(self, knowledge_dir: Path) -> None:
        self.knowledge_dir = knowledge_dir
        self.families = self._load_map(knowledge_dir / "weakness_family_ko.yaml")
        self.cwes = self._load_map(knowledge_dir / "cwe_ko.yaml")
        self.owasp = self._load_map(knowledge_dir / "owasp_ko.yaml")
        self.kisa = self._load_map(knowledge_dir / "kisa_ko.yaml")

    def describe_issue(self, issue: Any) -> dict[str, Any]:
        family = self.families.get(issue.weakness_family or "", {})
        cwe = self.cwes.get(issue.primary_cwe or "", {})
        owasp = self.owasp.get((issue.classification.owasp_top10_2025 or [""])[0], {})
        kisa = self.kisa.get((issue.classification.kisa_categories or [""])[0], {})
        return {
            "family": family,
            "cwe": cwe,
            "owasp": owasp,
            "kisa": kisa,
            "summary_ko": family.get("summary_ko") or cwe.get("summary_ko") or "관련 취약점에 대한 설명 정보가 아직 등록되지 않았습니다.",
            "risk_ko": family.get("risk_ko") or cwe.get("risk_ko") or "구체적인 영향도는 추가 검토가 필요합니다.",
            "validation_points_ko": family.get("validation_points_ko") or cwe.get("validation_points_ko") or ["증거와 구현 코드를 함께 재검토합니다."],
            "remediation_ko": family.get("remediation_ko") or cwe.get("remediation_ko") or ["보안 기준에 맞는 입력 검증과 설정 점검을 수행합니다."],
            "references": _merge_references(family, cwe, owasp, kisa),
        }

    @staticmethod
    def _load_map(path: Path) -> dict[str, dict[str, Any]]:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return {entry["id"]: entry for entry in payload.get("entries", []) if entry.get("id")}


def load_report_profile(profile_dir: Path, profile_name: str) -> dict[str, Any]:
    path = profile_dir / f"{profile_name}.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    payload.setdefault("id", profile_name)
    return payload


def load_report_template(template_dir: Path, template_name: str) -> dict[str, Any]:
    path = template_dir / f"{template_name}.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    payload.setdefault("id", template_name)
    return payload


def load_deliverable_profile(profile_dir: Path, profile_name: str) -> dict[str, Any]:
    path = profile_dir / f"{profile_name}.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    payload.setdefault("id", profile_name)
    return payload


def _merge_references(*items: dict[str, Any]) -> list[str]:
    merged: list[str] = []
    for item in items:
        for reference in item.get("references", []):
            if reference not in merged:
                merged.append(reference)
    return merged
