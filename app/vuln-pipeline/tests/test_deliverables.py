from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from vuln_pipeline.pipeline import run_pipeline


class DeliverableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-deliverables-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def _run(
        self,
        run_id: str,
        deliverable_profile: str,
        compare_to: Path | None = None,
        review_resolution: Path | None = None,
        release_candidate: bool = False,
        finalize_delivery: bool = False,
    ):
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
            review_resolution_path=review_resolution,
            compare_to_run=compare_to,
            ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
            report_profile="customer",
            knowledge_dir=self.project_root / "configs" / "knowledge",
            profile_dir=self.project_root / "configs" / "report_profiles",
            template_dir=self.project_root / "configs" / "report_templates",
            deliverable_profile_dir=self.project_root / "configs" / "deliverable_profiles",
            remediation_policy_dir=self.project_root / "configs" / "remediation_policy",
            readiness_policy_path=self.project_root / "configs" / "readiness" / "customer_release.yaml",
            report_template="default_customer",
            deliverable_profile=deliverable_profile,
            package_output=True,
            release_candidate=release_candidate,
            finalize_delivery=finalize_delivery,
            document_meta={
                "project_name": "Deliverable Test",
                "client_name": "Example Client",
                "engagement_name": "Delivery Pack",
                "analyst_name": "QA",
                "organization_name": "Org",
                "report_version": "v2.0",
                "delivery_date": "2026-03-15",
                "approver_name": "Approver",
                "contact_email": "qa@example.com",
            },
        )
        return bundle, output_root

    def test_review_resolution_applies_and_checklist_updates(self) -> None:
        _, output_root = self._run(
            "deliverable-resolution",
            "customer_pack",
            review_resolution=self.project_root / "tests" / "fixtures" / "realish" / "review_resolution.yaml",
        )
        queue = (output_root / "report_data" / "review_queue.jsonl").read_text(encoding="utf-8")
        checklist = next((output_root / "deliverables").glob("review_closure_checklist*.md")).read_text(encoding="utf-8")
        closure = json.loads((output_root / "report_data" / "review_closure_status.json").read_text(encoding="utf-8"))
        self.assertIn("resolution_status", queue)
        self.assertEqual(closure["unresolved_review_items"], 0)
        self.assertIn("DONE", checklist)

    def test_release_candidate_and_finalize_blocked_when_not_ready(self) -> None:
        _, output_root = self._run("deliverable-blocked", "customer_pack", release_candidate=True, finalize_delivery=True)
        candidate = json.loads((output_root / "report_data" / "release_candidate_manifest.json").read_text(encoding="utf-8"))
        final_delivery = json.loads((output_root / "delivery" / "final_delivery_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(candidate["readiness_status"], "conditionally_ready")
        self.assertFalse(final_delivery["final_ready"])

    def test_ready_allows_finalize_delivery(self) -> None:
        _, baseline_root = self._run("deliverable-ready-baseline", "customer_pack")
        _, output_root = self._run(
            "deliverable-ready",
            "customer_pack",
            compare_to=baseline_root,
            review_resolution=self.project_root / "tests" / "fixtures" / "realish" / "review_resolution.yaml",
            release_candidate=True,
            finalize_delivery=True,
        )
        readiness = json.loads((output_root / "report_data" / "release_readiness.json").read_text(encoding="utf-8"))
        final_delivery = json.loads((output_root / "delivery" / "final_delivery_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(readiness["status"], "ready")
        self.assertTrue(final_delivery["final_ready"])

    def test_manifest_and_pptx_fallback_details_present(self) -> None:
        _, output_root = self._run("deliverable-fallback", "management_pack")
        manifest = json.loads((output_root / "report_data" / "deliverables_manifest.json").read_text(encoding="utf-8"))
        fallback = next((output_root / "deliverables").glob("presentation_briefing*_fallback.json"))
        payload = json.loads(fallback.read_text(encoding="utf-8"))
        self.assertIn("readiness_policy", manifest)
        self.assertIn("install_hint", payload)
        self.assertIn("expected_output", payload)


if __name__ == "__main__":
    unittest.main()
