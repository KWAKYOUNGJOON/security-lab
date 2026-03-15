from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from vuln_pipeline.pipeline import run_pipeline


class OperationalFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-ops-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def _run(
        self,
        run_id: str,
        suppressions: Path | None = None,
        compare_to: Path | None = None,
        emit_override_template: bool = False,
        extra_nuclei: Path | None = None,
        package_output: bool = False,
    ):
        nuclei_inputs = [self.project_root / "tests" / "fixtures" / "realish" / "nuclei_rich.jsonl"]
        if extra_nuclei is not None:
            nuclei_inputs.append(extra_nuclei)
        output_root = self.output_base / run_id
        bundle = run_pipeline(
            run_id=run_id,
            inputs={
                "burp": [self.project_root / "tests" / "fixtures" / "realish" / "burp_complex.xml"],
                "nuclei": nuclei_inputs,
                "httpx": [self.project_root / "tests" / "fixtures" / "realish" / "httpx_rich.jsonl"],
            },
            output_root=output_root,
            mapping_config=self.project_root / "configs" / "mapping_rules.json",
            scoring_config=self.project_root / "configs" / "scoring_rules.json",
            override_path=self.project_root / "tests" / "fixtures" / "realish" / "override_realish.yaml",
            suppressions_path=suppressions,
            compare_to_run=compare_to,
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile="customer",
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            template_dir=self.project_root / "configs" / "report_templates",
            report_template="default_customer",
            emit_override_template=emit_override_template,
            package_output=package_output,
            document_meta={"project_name": "Ops Test", "client_name": "Client", "engagement_name": "RunOps", "analyst_name": "QA", "organization_name": "Org"},
        )
        return bundle, output_root

    def test_review_queue_and_override_template_generated(self) -> None:
        _, output_root = self._run("ops-review", emit_override_template=True)
        queue_jsonl = output_root / "report_data" / "review_queue.jsonl"
        queue_csv = output_root / "report_data" / "review_queue.csv"
        override_template = output_root / "report_data" / "override_template.yaml"
        self.assertTrue(queue_jsonl.exists())
        self.assertTrue(queue_csv.exists())
        self.assertTrue(override_template.exists())
        self.assertIn("issue_id", override_template.read_text(encoding="utf-8"))
        self.assertIn("priority_score", queue_jsonl.read_text(encoding="utf-8"))

    def test_suppression_applies_and_moves_issue_out_of_body(self) -> None:
        bundle, output_root = self._run(
            "ops-suppressed",
            suppressions=self.project_root / "tests" / "fixtures" / "realish" / "suppressions.yaml",
        )
        self.assertEqual(len(bundle.suppressed_issues), 1)
        report = (output_root / "reports" / "report.md").read_text(encoding="utf-8")
        self.assertIn("Suppressed / Accepted Risk 목록", report)
        self.assertIn("accepted_risk", report)

    def test_run_diff_and_qa_metrics_generated(self) -> None:
        _, baseline_root = self._run("ops-baseline")
        _, output_root = self._run("ops-compare", compare_to=baseline_root)
        diff_json = output_root / "comparison" / "run_diff.json"
        qa_json = output_root / "report_data" / "qa_metrics.json"
        self.assertTrue(diff_json.exists())
        self.assertTrue(qa_json.exists())
        diff_payload = json.loads(diff_json.read_text(encoding="utf-8"))
        qa_payload = json.loads(qa_json.read_text(encoding="utf-8"))
        self.assertTrue(diff_payload["available"])
        self.assertIn("review_queue_count", qa_payload)

    def test_parser_warnings_logged(self) -> None:
        _, output_root = self._run(
            "ops-warnings",
            extra_nuclei=self.project_root / "tests" / "fixtures" / "realish" / "nuclei_malformed.jsonl",
        )
        warnings_path = output_root / "report_data" / "ingest_warnings.jsonl"
        content = warnings_path.read_text(encoding="utf-8")
        self.assertIn("malformed_jsonl", content)
        self.assertIn("unknown_severity", content)

    def test_package_manifest_and_checksums_generated(self) -> None:
        _, output_root = self._run("ops-package", package_output=True)
        manifest = output_root / "delivery" / "delivery_manifest.json"
        checksums = output_root / "delivery" / "checksums.json"
        zip_path = output_root / "delivery" / "report_bundle_ops-package.zip"
        self.assertTrue(manifest.exists())
        self.assertTrue(checksums.exists())
        self.assertTrue(zip_path.exists())


if __name__ == "__main__":
    unittest.main()
