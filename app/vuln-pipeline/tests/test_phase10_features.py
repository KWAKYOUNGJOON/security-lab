from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from vuln_pipeline.cli.main import _apply_customer_bundle
from vuln_pipeline.pipeline import run_pipeline
from vuln_pipeline.report import build_customer_package_audit, build_input_preflight


class Phase10FeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-phase10-"))
        self.input_base = self.output_base / "inputs"
        for folder in ["burp", "nuclei", "httpx", "manual"]:
            (self.input_base / folder).mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def test_preflight_statuses_cover_blocked_warning_ready(self) -> None:
        blocked = build_input_preflight(
            explicit_inputs={"burp": None, "nuclei": None, "httpx": None},
            resolved_inputs={"burp": [], "nuclei": [], "httpx": []},
            roots={"burp": self.input_base / "burp", "nuclei": self.input_base / "nuclei", "httpx": self.input_base / "httpx"},
            manual_inputs={"override_file": None, "suppression_file": None, "review_resolution_file": None},
            auto_select_real_inputs=True,
        )
        self.assertEqual(blocked["status"], "blocked")

        burp_warning = self.input_base / "burp" / "customer.xml"
        burp_warning.write_text("<items>tiny</items>", encoding="utf-8")
        warning = build_input_preflight(
            explicit_inputs={"burp": [burp_warning], "nuclei": None, "httpx": None},
            resolved_inputs={"burp": [burp_warning], "nuclei": [], "httpx": []},
            roots={"burp": self.input_base / "burp", "nuclei": self.input_base / "nuclei", "httpx": self.input_base / "httpx"},
            manual_inputs={"override_file": burp_warning, "suppression_file": burp_warning, "review_resolution_file": burp_warning},
            auto_select_real_inputs=False,
        )
        self.assertEqual(warning["status"], "warning")

        burp_ready = self.input_base / "burp" / "customer-real.xml"
        nuclei_ready = self.input_base / "nuclei" / "customer-real.jsonl"
        httpx_ready = self.input_base / "httpx" / "customer-real.jsonl"
        burp_ready.write_text("<items>" + ("A" * 400) + "</items>", encoding="utf-8")
        nuclei_ready.write_text('{"info":"ok","detail":"' + ("N" * 180) + '"}\n{"info":"ok2","detail":"' + ("M" * 180) + '"}\n', encoding="utf-8")
        httpx_ready.write_text('{"url":"https://a","title":"' + ("H" * 180) + '"}\n{"url":"https://b","title":"' + ("I" * 180) + '"}\n', encoding="utf-8")
        override = self.input_base / "manual" / "override_real.yaml"
        suppression = self.input_base / "manual" / "suppression_real.yaml"
        resolution = self.input_base / "manual" / "review_resolution_real.yaml"
        for path in [override, suppression, resolution]:
            path.write_text("enabled: true\n", encoding="utf-8")
        ready = build_input_preflight(
            explicit_inputs={"burp": [burp_ready], "nuclei": [nuclei_ready], "httpx": [httpx_ready]},
            resolved_inputs={"burp": [burp_ready], "nuclei": [nuclei_ready], "httpx": [httpx_ready]},
            roots={"burp": self.input_base / "burp", "nuclei": self.input_base / "nuclei", "httpx": self.input_base / "httpx"},
            manual_inputs={"override_file": override, "suppression_file": suppression, "review_resolution_file": resolution},
            auto_select_real_inputs=False,
        )
        self.assertEqual(ready["status"], "ready")

    def test_real_preflight_blocks_legacy_default_manual_sources(self) -> None:
        burp_ready = self.input_base / "burp" / "customer-real.xml"
        nuclei_ready = self.input_base / "nuclei" / "customer-real.jsonl"
        httpx_ready = self.input_base / "httpx" / "customer-real.jsonl"
        burp_ready.write_text("<items>" + ("A" * 400) + "</items>", encoding="utf-8")
        nuclei_ready.write_text('{"info":"ok","detail":"' + ("N" * 180) + '"}\n{"info":"ok2","detail":"' + ("M" * 180) + '"}\n', encoding="utf-8")
        httpx_ready.write_text('{"url":"https://a","title":"' + ("H" * 180) + '"}\n{"url":"https://b","title":"' + ("I" * 180) + '"}\n', encoding="utf-8")
        legacy_override = self.input_base / "manual" / "sample_override.yaml"
        legacy_suppression = self.input_base / "manual" / "suppressions.yaml"
        legacy_review = self.input_base / "manual" / "review_resolution.yaml"
        for path in [legacy_override, legacy_suppression, legacy_review]:
            path.write_text("enabled: true\n", encoding="utf-8")

        blocked = build_input_preflight(
            explicit_inputs={"burp": [burp_ready], "nuclei": [nuclei_ready], "httpx": [httpx_ready]},
            resolved_inputs={"burp": [burp_ready], "nuclei": [nuclei_ready], "httpx": [httpx_ready]},
            roots={"burp": self.input_base / "burp", "nuclei": self.input_base / "nuclei", "httpx": self.input_base / "httpx"},
            manual_inputs={
                "override_file": legacy_override,
                "suppression_file": legacy_suppression,
                "review_resolution_file": legacy_review,
            },
            manual_metadata={
                "override_file": {"manual_source": "legacy_default", "effective_path": str(legacy_override)},
                "suppression_file": {"manual_source": "legacy_default", "effective_path": str(legacy_suppression)},
                "review_resolution_file": {"manual_source": "legacy_default", "effective_path": str(legacy_review)},
            },
            auto_select_real_inputs=True,
        )
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["manual_inputs"]["override_file"]["manual_source"], "legacy_default")
        self.assertIn("expected `real_explicit`", "\n".join(blocked["blockers"]))

    def test_customer_package_audit_pass_and_fail(self) -> None:
        passed = build_customer_package_audit(
            run_root=self.output_base,
            included_files=[
                "deliverables/full_report_customer_customer_v1.0.md",
                "deliverables/executive_onepager_customer_v1.0.md",
                "delivery/final_delivery_manifest.json",
            ],
            excluded_files=["report_data/review_queue.jsonl"],
        )
        self.assertEqual(passed["audit_result"], "pass")

        failed = build_customer_package_audit(
            run_root=self.output_base,
            included_files=[
                "deliverables/full_report_customer_customer_v1.0.md",
                "report_data/review_queue.jsonl",
            ],
            excluded_files=[],
        )
        self.assertEqual(failed["audit_result"], "fail")

    def test_archive_only_run_generates_internal_archive_manifest_only(self) -> None:
        output_root = self.output_base / "archive-only"
        run_pipeline(
            run_id="archive-only",
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
            archive_only=True,
            document_meta={"project_name": "Phase10", "client_name": "Client", "report_version": "v10.0"},
            execution_options={"run_id": "archive-only"},
        )
        self.assertTrue((output_root / "delivery" / "internal_archive_v10.0.zip").exists())
        self.assertTrue((output_root / "report_data" / "archive_only_manifest.json").exists())
        self.assertFalse((output_root / "delivery" / "customer_submission_v10.0.zip").exists())

    def test_pptx_capability_and_final_check_outputs_exist(self) -> None:
        output_root = self.output_base / "pptx-check"
        run_pipeline(
            run_id="pptx-check",
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
            require_pptx=True,
            document_meta={"project_name": "Phase10", "client_name": "Client", "report_version": "v10.0"},
            execution_options={"run_id": "pptx-check"},
        )
        capability = json.loads((output_root / "report_data" / "pptx_capability.json").read_text(encoding="utf-8"))
        final_check = (output_root / "deliverables" / "final_submission_check.md").read_text(encoding="utf-8")
        self.assertIn("dependency_found", capability)
        self.assertIn("PPTX capability", final_check)

    def test_customer_bundle_merge_prefers_explicit_values(self) -> None:
        args = Namespace(
            customer_bundle=self.project_root / "configs" / "customer_bundles" / "default_customer_release.yaml",
            branding_file=Path("explicit-branding.yaml"),
            report_template="default_internal",
            deliverable_profile="internal_pack",
            readiness_policy=Path("explicit-readiness.yaml"),
            remediation_policy_dir=Path("explicit-remediation"),
            report_profile="internal",
        )
        _apply_customer_bundle(args, {"--branding-file", "--report-template"})
        self.assertEqual(args.branding_file, Path("explicit-branding.yaml"))
        self.assertEqual(args.report_template, "default_internal")
        self.assertEqual(args.deliverable_profile, "customer_pack")
        self.assertEqual(args.report_profile, "customer")


if __name__ == "__main__":
    unittest.main()
