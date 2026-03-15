from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from vuln_pipeline.parsers.real_inputs import auto_select_real_inputs
from vuln_pipeline.pipeline import run_pipeline


class Phase9FeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-phase9-"))
        self.input_base = self.output_base / "real-inputs"
        for folder in ["burp", "nuclei", "httpx", "manual"]:
            (self.input_base / folder).mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def _run_ready(self, run_id: str, require_pptx: bool = False):
        baseline_root = self.output_base / f"{run_id}-baseline"
        run_pipeline(
            run_id=f"{run_id}-baseline",
            inputs={
                "burp": [self.project_root / "tests" / "fixtures" / "realish" / "burp_complex.xml"],
                "nuclei": [self.project_root / "tests" / "fixtures" / "realish" / "nuclei_rich.jsonl"],
                "httpx": [self.project_root / "tests" / "fixtures" / "realish" / "httpx_rich.jsonl"],
            },
            output_root=baseline_root,
            mapping_config=self.project_root / "configs" / "mapping_rules.json",
            scoring_config=self.project_root / "configs" / "scoring_rules.json",
            override_path=self.project_root / "tests" / "fixtures" / "realish" / "override_realish.yaml",
            suppressions_path=self.project_root / "tests" / "fixtures" / "realish" / "suppressions.yaml",
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile="customer",
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            template_dir=self.project_root / "configs" / "report_templates",
            deliverable_profile_dir=self.project_root / "configs" / "deliverable_profiles",
            remediation_policy_dir=self.project_root / "configs" / "remediation_policy",
            readiness_policy_path=self.project_root / "configs" / "readiness" / "customer_release.yaml",
            report_template="default_customer",
            deliverable_profile="customer_pack",
            package_output=True,
            branding_path=self.project_root / "configs" / "branding" / "customer_branding.yaml",
            document_meta={"project_name": "Phase9", "client_name": "Example Client", "engagement_name": "Final", "analyst_name": "QA", "organization_name": "Security"},
        )
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
            suppressions_path=self.project_root / "tests" / "fixtures" / "realish" / "suppressions.yaml",
            review_resolution_path=self.project_root / "tests" / "fixtures" / "realish" / "review_resolution.yaml",
            compare_to_run=baseline_root,
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile="customer",
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            template_dir=self.project_root / "configs" / "report_templates",
            deliverable_profile_dir=self.project_root / "configs" / "deliverable_profiles",
            remediation_policy_dir=self.project_root / "configs" / "remediation_policy",
            readiness_policy_path=self.project_root / "configs" / "readiness" / "customer_release.yaml",
            report_template="default_customer",
            deliverable_profile="customer_pack",
            package_output=True,
            finalize_delivery=True,
            branding_path=self.project_root / "configs" / "branding" / "customer_branding.yaml",
            require_pptx=require_pptx,
            real_input_selection={
                "status": "selected",
                "selected_run_inputs": [
                    str(self.project_root / "tests" / "fixtures" / "realish" / "burp_complex.xml"),
                    str(self.project_root / "tests" / "fixtures" / "realish" / "nuclei_rich.jsonl"),
                ],
                "notes": [],
            },
            document_meta={
                "project_name": "Phase9",
                "client_name": "Example Client",
                "engagement_name": "Final",
                "analyst_name": "QA",
                "organization_name": "Security",
                "report_version": "v9.0",
                "delivery_date": "2026-03-15",
                "approver_name": "Approver",
                "contact_email": "qa@example.com",
            },
        )
        return bundle, output_root

    def test_auto_select_real_inputs_prefers_latest_non_sample(self) -> None:
        burp_dir = self.input_base / "burp"
        (burp_dir / "burp_sample.xml").write_text("<sample/>", encoding="utf-8")
        valid = burp_dir / "customer_export.xml"
        valid.write_text("<items>" + ("A" * 400) + "</items>", encoding="utf-8")
        newer = burp_dir / "recent_customer.xml"
        newer.write_text("<items>" + ("B" * 500) + "</items>", encoding="utf-8")
        valid_stat = valid.stat()
        os.utime(newer, (valid_stat.st_atime + 60, valid_stat.st_mtime + 60))
        selected, manifest = auto_select_real_inputs(
            roots={"burp": burp_dir, "nuclei": self.input_base / "nuclei", "httpx": self.input_base / "httpx"},
            manual_dir=self.input_base / "manual",
        )
        self.assertEqual(selected["burp"], [newer])
        self.assertEqual(manifest["status"], "selected")
        self.assertIn("burp_sample.xml", json.dumps(manifest["tools"]["burp"]["evaluated_candidates"], ensure_ascii=False))

    def test_customer_and_internal_packages_are_split(self) -> None:
        _, output_root = self._run_ready("phase9-packages")
        customer_zip = output_root / "delivery" / "customer_submission_v9.0.zip"
        internal_zip = output_root / "delivery" / "internal_archive_v9.0.zip"
        self.assertTrue(customer_zip.exists())
        self.assertTrue(internal_zip.exists())
        with ZipFile(customer_zip) as archive:
            names = archive.namelist()
            self.assertTrue(any(name.endswith("deliverables/full_report_customer_customer_v9.0.docx") for name in names))
            self.assertFalse(any("review_queue" in name for name in names))
            self.assertFalse(any("analyst_handoff" in name for name in names))
        with ZipFile(internal_zip) as archive:
            names = archive.namelist()
            self.assertTrue(any("report_data/review_queue.jsonl" in name for name in names))
            self.assertTrue(any("deliverables/submission_memo.md" in name for name in names))

    def test_submission_gate_branding_closeout_and_rehearsal_outputs_exist(self) -> None:
        _, output_root = self._run_ready("phase9-gate")
        gate = json.loads((output_root / "report_data" / "submission_gate.json").read_text(encoding="utf-8"))
        manifest = json.loads((output_root / "delivery" / "final_delivery_manifest.json").read_text(encoding="utf-8"))
        deliverables_manifest = json.loads((output_root / "report_data" / "deliverables_manifest.json").read_text(encoding="utf-8"))
        onepager = next((output_root / "deliverables").glob("executive_onepager*.md")).read_text(encoding="utf-8")
        tracker = next((output_root / "deliverables").glob("remediation_tracker*.md")).read_text(encoding="utf-8")
        submission_memo = (output_root / "deliverables" / "submission_memo.md").read_text(encoding="utf-8")
        rehearsal = (output_root / "deliverables" / "real_data_rehearsal_summary.md").read_text(encoding="utf-8")
        self.assertEqual(gate["status"], "pass")
        self.assertTrue(manifest["final_ready"])
        self.assertTrue(deliverables_manifest["branding_applied"])
        self.assertIn("resolved review count", onepager)
        self.assertIn("| Closeout |", tracker)
        self.assertIn("Unresolved review items at submission time: 0.", submission_memo)
        self.assertIn("status: `completed`", rehearsal)

    def test_require_pptx_blocks_finalization_when_dependency_missing(self) -> None:
        _, output_root = self._run_ready("phase9-require-pptx", require_pptx=True)
        gate = json.loads((output_root / "report_data" / "submission_gate.json").read_text(encoding="utf-8"))
        manifest = json.loads((output_root / "delivery" / "final_delivery_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(gate["status"], "fail")
        self.assertFalse(manifest["final_ready"])


if __name__ == "__main__":
    unittest.main()
