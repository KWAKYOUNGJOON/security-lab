from __future__ import annotations

import unittest
from pathlib import Path

from vuln_pipeline.mapping import RuleEngine
from vuln_pipeline.models import AssetRef, ParsedFinding
from vuln_pipeline.normalize import normalize_finding
from vuln_pipeline.scoring import score_finding


class MappingAndScoringTests(unittest.TestCase):
    def test_sqli_rule_and_score(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        finding = normalize_finding(
            ParsedFinding(
                source="burp",
                source_file="sample.xml",
                parser="burp_xml",
                raw_id="1",
                kind="finding",
                title="SQL Injection",
                description="desc",
                asset=AssetRef(
                    url="https://demo.example.com/users/123?id=1",
                    host="demo.example.com",
                    path="/users/123",
                    normalized_path=None,
                    method="get",
                ),
                raw_severity="High",
                raw_confidence="Certain",
            ),
            run_id="r1",
            index=1,
        )
        mapped = RuleEngine(project_root / "configs" / "mapping_rules.json").apply(finding)
        scored = score_finding(mapped, project_root / "configs" / "scoring_rules.json")
        self.assertEqual(scored.classification.primary_cwe, "CWE-89")
        self.assertEqual(scored.classification.weakness_family, "SQL Injection")
        self.assertEqual(scored.severity.level, "Critical")
        self.assertEqual(scored.confidence.level, "High")


if __name__ == "__main__":
    unittest.main()
