from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from vuln_pipeline.pipeline import run_pipeline


class ReportingFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-report-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def _run(self, run_id: str, profile: str, template: str, package_output: bool = False):
        output_root = self.output_base / run_id
        bundle = run_pipeline(
            run_id=run_id,
            inputs={
                "burp": [self.project_root / "tests" / "fixtures" / "realish" / "burp_complex.xml"],
                "nuclei": [self.project_root / "tests" / "fixtures" / "realish" / "nuclei_rich.jsonl"],
                "httpx": [self.project_root / "tests" / "fixtures" / "realish" / "httpx_rich.jsonl"],
            },
            output_root=output_root,
            mapping_config=self.project_root / "configs" / "mapping_rules.json",
            scoring_config=self.project_root / "configs" / "scoring_rules.json",
            override_path=self.project_root / "tests" / "fixtures" / "realish" / "override_realish.yaml",
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile=profile,
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            template_dir=self.project_root / "configs" / "report_templates",
            report_template=template,
            package_output=package_output,
            document_meta={
                "project_name": "Portal Security Review",
                "client_name": "Example Client",
                "engagement_name": "Q1 Web Assessment",
                "analyst_name": "QA Analyst",
                "organization_name": "Security Org",
            },
        )
        return bundle, output_root

    def test_executive_summary_and_remediation_plan_present(self) -> None:
        _, output_root = self._run("reporting-internal", "internal", "default_internal")
        report = (output_root / "reports" / "report.md").read_text(encoding="utf-8")
        self.assertIn("Executive Summary", report)
        self.assertIn("Remediation Plan", report)
        self.assertIn("Issue ID | Title | Severity", report)

    def test_customer_profile_reduces_raw_path_exposure(self) -> None:
        _, internal_root = self._run("internal-compare", "internal", "default_internal")
        _, customer_root = self._run("customer-compare", "customer", "default_customer")
        internal_report = (internal_root / "reports" / "report.md").read_text(encoding="utf-8")
        customer_report = (customer_root / "reports" / "report.md").read_text(encoding="utf-8")
        self.assertTrue("/raw/" in internal_report or "\\raw\\" in internal_report)
        self.assertNotIn("/raw/", customer_report)
        self.assertNotIn("\\raw\\", customer_report)
        self.assertIn("burp_001_error-disclosure_request.txt", customer_report)

    def test_template_and_package_output(self) -> None:
        _, output_root = self._run("packaged-customer", "customer", "default_customer", package_output=True)
        report = (output_root / "reports" / "report.md").read_text(encoding="utf-8")
        self.assertIn("고객 제출용 요약 보고서", report)
        zip_path = output_root / "delivery" / "report_bundle_packaged-customer.zip"
        self.assertTrue(zip_path.exists())
        with ZipFile(zip_path) as archive:
            names = archive.namelist()
            self.assertTrue(any(name.endswith("reports/report.md") for name in names))
            self.assertFalse(any("/raw/" in name or "\\raw\\" in name for name in names))


if __name__ == "__main__":
    unittest.main()
