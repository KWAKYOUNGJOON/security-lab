from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vuln_pipeline.models import Classification, NormalizedFinding


class RuleEngine:
    def __init__(self, config_path: Path) -> None:
        self.config = json.loads(config_path.read_text(encoding="utf-8"))

    def apply(
        self,
        finding: NormalizedFinding,
        return_decision: bool = False,
    ) -> NormalizedFinding | tuple[NormalizedFinding, dict[str, Any]]:
        rules = sorted(
            enumerate(self.config["rules"]),
            key=lambda item: (item[1].get("priority", 100), -item[0]),
            reverse=True,
        )
        matched_candidates: list[dict[str, Any]] = []
        rejected_rules: list[str] = []
        rejection_reasons: dict[str, str] = {}
        selected_rule = None
        selected_detail = None

        for _, rule in rules:
            matched, detail = self._matches(rule, finding)
            if matched:
                matched_candidates.append(detail)
                if selected_rule is None:
                    selected_rule = rule
                    selected_detail = detail
                    if rule.get("stop_on_match", True):
                        continue
            else:
                rejected_rules.append(rule.get("id", "unknown"))
                rejection_reasons[rule.get("id", "unknown")] = detail.get("reason", "not_matched")

        if selected_rule:
            finding.classification = Classification(
                weakness_family=selected_rule.get("weakness_family"),
                primary_cwe=selected_rule.get("primary_cwe"),
                related_cwes=selected_rule.get("related_cwes", []),
                owasp_top10_2025=selected_rule.get("owasp_top10_2025", []),
                kisa_categories=selected_rule.get("kisa_categories", []),
                parameter_or_sink=self._guess_parameter_or_sink(finding),
                matched_rule_id=selected_rule.get("id"),
            )
            finding.references = sorted(set(finding.references + selected_rule.get("references", [])))
            for detail in matched_candidates:
                if detail["rule_id"] != selected_rule.get("id"):
                    rejected_rules.append(detail["rule_id"])
                    rejection_reasons[detail["rule_id"]] = "lower_priority_than_selected"
        else:
            finding.classification.parameter_or_sink = self._guess_parameter_or_sink(finding)

        decision = {
            "finding_id": finding.finding_id,
            "source": finding.source,
            "title": finding.title,
            "selected_rule": selected_rule.get("id") if selected_rule else None,
            "selected_rule_detail": selected_detail,
            "candidate_rules": [detail["rule_id"] for detail in matched_candidates],
            "rejected_rules": rejected_rules,
            "rejection_reasons": rejection_reasons,
            "classification": finding.classification,
        }
        return (finding, decision) if return_decision else finding

    def _matches(self, rule: dict[str, Any], finding: NormalizedFinding) -> tuple[bool, dict[str, Any]]:
        rule_id = rule.get("id", "unknown")
        mode = rule.get("logic", "any").lower()
        tool_match = self._match_tool(rule, finding)
        if tool_match is False:
            return False, {"rule_id": rule_id, "matched": False, "reason": "tool_mismatch"}
        negative = self._evaluate_negative_conditions(rule, finding)
        if negative:
            return False, {"rule_id": rule_id, "matched": False, "reason": negative}

        checks = {
            "title_contains": self._match_title_contains(rule, finding),
            "title_regex": self._match_title_regex(rule, finding),
            "template_ids": self._match_template_id(rule, finding),
            "tags_any": self._match_tags(rule, finding),
            "host_contains": self._match_host(rule, finding),
            "path_contains": self._match_path(rule, finding),
            "parameter_contains": self._match_parameter(rule, finding),
            "response_highlight_contains": self._match_highlight(rule, finding),
        }
        active = {key: value for key, value in checks.items() if value is not None}
        if not active:
            return False, {"rule_id": rule_id, "matched": False, "reason": "no_active_conditions"}
        matched = all(active.values()) if mode == "all" else any(active.values())
        if not matched:
            return False, {"rule_id": rule_id, "matched": False, "reason": "positive_conditions_not_met", "checks": active}
        return (
            True,
            {
                "rule_id": rule_id,
                "matched": True,
                "priority": rule.get("priority", 100),
                "stop_on_match": rule.get("stop_on_match", True),
                "logic": mode,
                "tool_match": tool_match,
                "checks": active,
            },
        )

    def _evaluate_negative_conditions(self, rule: dict[str, Any], finding: NormalizedFinding) -> str | None:
        title = finding.title
        path = finding.asset.normalized_path or finding.asset.path or ""
        tags = set(finding.tags)
        for pattern in rule.get("negative_title_regex", []):
            if re.search(pattern, title, re.IGNORECASE):
                return "negative_title_regex"
        for pattern in rule.get("negative_path_regex", []):
            if re.search(pattern, path, re.IGNORECASE):
                return "negative_path_regex"
        negative_tags = set(rule.get("negative_tags", []))
        if negative_tags and tags.intersection(negative_tags):
            return "negative_tags"
        return None

    def _match_tool(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("tools")
        return None if not values else finding.source in values

    def _match_title_contains(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("title_contains")
        return None if not values else any(value.lower() in finding.title for value in values)

    def _match_title_regex(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("title_regex")
        return None if not values else any(re.search(pattern, finding.title, re.IGNORECASE) for pattern in values)

    def _match_template_id(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("template_ids")
        template_id = finding.raw.get("metadata", {}).get("template_id")
        return None if not values else template_id in values

    def _match_tags(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("tags_any")
        return None if not values else bool(set(finding.tags).intersection(values))

    def _match_host(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("host_contains")
        host = finding.asset.host or ""
        return None if not values else any(value.lower() in host.lower() for value in values)

    def _match_path(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("path_contains")
        path = finding.asset.normalized_path or finding.asset.path or ""
        return None if not values else any(value.lower() in path.lower() for value in values)

    def _match_parameter(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("parameter_contains")
        params = ",".join(finding.asset.query_keys)
        return None if not values else any(value.lower() in params.lower() for value in values)

    def _match_highlight(self, rule: dict[str, Any], finding: NormalizedFinding) -> bool | None:
        values = rule.get("response_highlight_contains")
        haystack = " ".join(
            [highlight for evidence in finding.evidence for highlight in evidence.highlights + evidence.extracted_results]
        )
        return None if not values else any(value.lower() in haystack.lower() for value in values)

    @staticmethod
    def _guess_parameter_or_sink(finding: NormalizedFinding) -> str | None:
        if finding.asset.query_keys:
            return ",".join(finding.asset.query_keys)
        metadata = finding.raw.get("metadata", {})
        if metadata.get("matcher_name"):
            return str(metadata["matcher_name"])
        return finding.classification.parameter_or_sink
