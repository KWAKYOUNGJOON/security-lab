from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from docx import Document

from vuln_pipeline.parsers.ingest import collect_inputs
from vuln_pipeline.pipeline import run_pipeline
from vuln_pipeline.report.context import build_report_context
from vuln_pipeline.report.knowledge import KnowledgePack


class PipelineIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def _run(self, run_id: str, profile: str = "internal"):
        output_root = self.output_base / run_id
        bundle = run_pipeline(
            run_id=run_id,
            inputs={
                "burp": [self.project_root / "tests" / "fixtures" / "burp_sample.xml"],
                "nuclei": [self.project_root / "tests" / "fixtures" / "nuclei_sample.jsonl"],
                "httpx": [self.project_root / "tests" / "fixtures" / "httpx_sample.jsonl"],
            },
            output_root=output_root,
            mapping_config=self.project_root / "configs" / "mapping_rules.json",
            scoring_config=self.project_root / "configs" / "scoring_rules.json",
            override_path=self.project_root / "tests" / "fixtures" / "sample_override.yaml",
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile=profile,
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
        )
        return bundle, output_root

    def test_end_to_end_bundle_and_report(self) -> None:
        bundle, output_root = self._run("test-run")
        self.assertEqual(bundle.summary["parsed_findings"], 3)
        self.assertEqual(bundle.summary["issues"], 2)
        self.assertTrue((output_root / "parsed" / "parsed_findings.json").exists())
        self.assertTrue((output_root / "normalized" / "normalized_findings.json").exists())
        self.assertTrue((output_root / "issues" / "issue_clusters.json").exists())
        self.assertTrue((output_root / "report_data" / "final_report_bundle.json").exists())
        self.assertTrue((output_root / "report_data" / "report_context.json").exists())
        self.assertTrue((output_root / "report_data" / "mapping_decisions.jsonl").exists())
        self.assertTrue((output_root / "report_data" / "override_decisions.jsonl").exists())
        report_path = output_root / "reports" / "report.md"
        self.assertTrue(report_path.exists())
        self.assertIn("Executive Summary", report_path.read_text(encoding="utf-8"))
        docx_path = output_root / "reports" / "report.docx"
        self.assertTrue(docx_path.exists())
        self.assertTrue(any("웹 취약점 진단 보고서" in paragraph.text for paragraph in Document(docx_path).paragraphs))

    def test_batch_ingest_manifest(self) -> None:
        fixtures = self.project_root / "tests" / "fixtures"
        inputs, manifest = collect_inputs(
            explicit={"burp": None, "nuclei": None, "httpx": None},
            directories={"burp": fixtures, "nuclei": fixtures, "httpx": fixtures},
        )
        self.assertTrue(inputs["burp"])
        self.assertTrue(inputs["nuclei"])
        self.assertTrue(inputs["httpx"])
        self.assertIn("ingested", manifest)

    def test_knowledge_pack_fallback(self) -> None:
        pack = KnowledgePack(self.project_root / "configs" / "knowledge")

        class Dummy:
            weakness_family = "Unknown Family"
            primary_cwe = None
            classification = type("Classification", (), {"owasp_top10_2025": [], "kisa_categories": []})()

        description = pack.describe_issue(Dummy())
        self.assertIn("설명 정보", description["summary_ko"])

    def test_report_profiles_expose_different_details(self) -> None:
        bundle, output_root = self._run("profile-run", profile="customer")
        customer = build_report_context(
            bundle=bundle,
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            profile_name="customer",
            report_data_dir=output_root / "report_data",
        )
        internal = build_report_context(
            bundle=bundle,
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            profile_name="internal",
            report_data_dir=output_root / "report_data",
        )
        self.assertFalse(customer["profile"]["show_raw_artifacts"])
        self.assertFalse(customer["profile"]["show_internal_paths"])
        self.assertTrue(internal["profile"]["show_raw_artifacts"])

    def test_override_reflected_in_narrative_and_remediation(self) -> None:
        bundle, output_root = self._run("narrative-run", profile="internal")
        context = build_report_context(
            bundle=bundle,
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            profile_name="internal",
            report_data_dir=output_root / "report_data",
        )
        first = context["narratives"][0]["narrative"]
        self.assertIn("parameterized queries", " ".join(first["quick_fix"]).lower())
        self.assertIn("Manually confirmed", first["analyst_note"])


if __name__ == "__main__":
    unittest.main()
