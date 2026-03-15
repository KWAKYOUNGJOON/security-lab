from __future__ import annotations

import unittest
from pathlib import Path

from vuln_pipeline.mapping import RuleEngine
from vuln_pipeline.models import AssetRef, EvidenceItem, ParsedFinding
from vuln_pipeline.normalize import normalize_finding


class RuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.engine = RuleEngine(self.project_root / "configs" / "mapping_rules.json")

    def test_priority_selects_more_specific_rule(self) -> None:
        finding = normalize_finding(
            ParsedFinding(
                source="nuclei",
                source_file="sample.jsonl",
                parser="nuclei_jsonl",
                raw_id="xss-rich",
                kind="finding",
                title="Reflected XSS",
                description="desc",
                asset=AssetRef(
                    url="https://portal.example.com/search?q=%3Cscript%3E",
                    host="portal.example.com",
                    path="/search",
                    normalized_path=None,
                    method="get",
                ),
                raw_severity="medium",
                tags=["xss"],
                metadata={"template_id": "xss-rich"},
            ),
            run_id="r1",
            index=1,
        )
        finding.evidence = [EvidenceItem(type="match", summary="match", highlights=["<script>alert(1)</script>"])]
        finding.raw["metadata"]["template_id"] = "xss-rich"
        mapped, decision = self.engine.apply(finding, return_decision=True)
        self.assertEqual(mapped.classification.matched_rule_id, "reflected-xss-specific")
        self.assertIn("xss", decision["rejected_rules"])
        self.assertEqual(decision["rejection_reasons"]["xss"], "lower_priority_than_selected")

    def test_negative_tags_block_wrong_mapping(self) -> None:
        finding = normalize_finding(
            ParsedFinding(
                source="nuclei",
                source_file="sample.jsonl",
                parser="nuclei_jsonl",
                raw_id="mixed",
                kind="finding",
                title="Potential Input Reflection",
                description="desc",
                asset=AssetRef(
                    url="https://portal.example.com/files/1?id=1",
                    host="portal.example.com",
                    path="/files/1",
                    normalized_path=None,
                    method="get",
                ),
                raw_severity="info",
                tags=["listing", "xss"],
                metadata={"template_id": "generic-sqli-lookalike"},
            ),
            run_id="r1",
            index=2,
        )
        mapped, decision = self.engine.apply(finding, return_decision=True)
        self.assertNotEqual(mapped.classification.matched_rule_id, "sql-injection")
        self.assertEqual(decision["rejection_reasons"]["sql-injection"], "negative_tags")


if __name__ == "__main__":
    unittest.main()
