from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from vuln_pipeline.parsers.real_inputs import auto_select_real_inputs, resolve_manual_input_paths
from vuln_pipeline.pipeline import run_pipeline
from vuln_pipeline.report import build_customer_package_audit


class Phase11FeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-phase11-"))
        self.real_root = self.output_base / "real"
        self.legacy_root = self.output_base / "legacy"
        for base in [self.real_root, self.legacy_root]:
            for folder in ["burp", "nuclei", "httpx", "manual"]:
                (base / folder).mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.output_base, ignore_errors=True)

    def test_real_directory_priority_and_hash_manifest(self) -> None:
        real_burp = self.real_root / "burp" / "customer.xml"
        legacy_burp = self.legacy_root / "burp" / "legacy.xml"
        real_burp.write_text("<items>" + ("R" * 400) + "</items>", encoding="utf-8")
        legacy_burp.write_text("<items>" + ("L" * 800) + "</items>", encoding="utf-8")
        selected, manifest, intake, hashes = auto_select_real_inputs(
            primary_roots={"burp": self.real_root / "burp", "nuclei": self.real_root / "nuclei", "httpx": self.real_root / "httpx"},
            fallback_roots={"burp": self.legacy_root / "burp", "nuclei": self.legacy_root / "nuclei", "httpx": self.legacy_root / "httpx"},
            primary_manual_dir=self.real_root / "manual",
            fallback_manual_dir=self.legacy_root / "manual",
        )
        self.assertEqual(selected["burp"], [real_burp])
        self.assertEqual(manifest["tools"]["burp"]["source_priority"], "real")
        self.assertTrue(any(entry["source_path"] == str(real_burp) for entry in intake["entries"]))
        self.assertTrue(any(entry["source_path"] == str(real_burp) and entry["sha256"] for entry in hashes["entries"]))

    def test_stage_real_inputs_copies_snapshot(self) -> None:
        real_nuclei = self.real_root / "nuclei" / "customer.jsonl"
        real_nuclei.write_text('{"id":1,"detail":"' + ("A" * 180) + '"}\n{"id":2,"detail":"' + ("B" * 180) + '"}\n', encoding="utf-8")
        _, _, intake, _ = auto_select_real_inputs(
            primary_roots={"burp": self.real_root / "burp", "nuclei": self.real_root / "nuclei", "httpx": self.real_root / "httpx"},
            fallback_roots={"burp": self.legacy_root / "burp", "nuclei": self.legacy_root / "nuclei", "httpx": self.legacy_root / "httpx"},
            primary_manual_dir=self.real_root / "manual",
            fallback_manual_dir=self.legacy_root / "manual",
            snapshot_root=self.output_base / "snapshot",
            stage_selected=True,
        )
        selected_entry = next(entry for entry in intake["entries"] if entry["source_path"] == str(real_nuclei))
        self.assertEqual(selected_entry["copied_or_referenced"], "copied")
        self.assertTrue(Path(selected_entry["snapshot_path"]).exists())

    def test_real_manual_selection_marks_real_explicit_and_replaces_legacy_default(self) -> None:
        real_override = self.real_root / "manual" / "override_real.yaml"
        real_suppression = self.real_root / "manual" / "suppression_real.yaml"
        real_review = self.real_root / "manual" / "review_resolution_real.yaml"
        for path in [real_override, real_suppression, real_review]:
            path.write_text("enabled: true\n", encoding="utf-8")

        _, selection, _, _ = auto_select_real_inputs(
            primary_roots={"burp": self.real_root / "burp", "nuclei": self.real_root / "nuclei", "httpx": self.real_root / "httpx"},
            fallback_roots={"burp": self.legacy_root / "burp", "nuclei": self.legacy_root / "nuclei", "httpx": self.legacy_root / "httpx"},
            primary_manual_dir=self.real_root / "manual",
            fallback_manual_dir=self.legacy_root / "manual",
        )
        defaults = {
            "override_file": self.legacy_root / "manual" / "sample_override.yaml",
            "suppression_file": self.legacy_root / "manual" / "suppressions.yaml",
            "review_resolution_file": self.legacy_root / "manual" / "review_resolution.yaml",
        }
        resolved, metadata = resolve_manual_input_paths(
            configured_manual_inputs=defaults,
            default_manual_inputs=defaults,
            explicit_flags=set(),
            auto_select_real_inputs=True,
            real_input_selection=selection,
            real_manual_dir=self.real_root / "manual",
            legacy_manual_dir=self.legacy_root / "manual",
        )
        self.assertEqual(resolved["override_file"], real_override)
        self.assertEqual(metadata["override_file"]["manual_source"], "real_explicit")
        self.assertEqual(metadata["suppression_file"]["manual_source"], "real_explicit")
        self.assertEqual(metadata["review_resolution_file"]["manual_source"], "real_explicit")

    def test_legacy_default_manual_is_not_treated_as_real_explicit(self) -> None:
        defaults = {
            "override_file": self.legacy_root / "manual" / "sample_override.yaml",
            "suppression_file": self.legacy_root / "manual" / "suppressions.yaml",
            "review_resolution_file": self.legacy_root / "manual" / "review_resolution.yaml",
        }
        for path in defaults.values():
            path.write_text("enabled: true\n", encoding="utf-8")

        resolved, metadata = resolve_manual_input_paths(
            configured_manual_inputs=defaults,
            default_manual_inputs=defaults,
            explicit_flags=set(),
            auto_select_real_inputs=True,
            real_input_selection={"manual_support": {}},
            real_manual_dir=self.real_root / "manual",
            legacy_manual_dir=self.legacy_root / "manual",
        )
        self.assertEqual(resolved["override_file"], defaults["override_file"])
        self.assertEqual(metadata["override_file"]["manual_source"], "legacy_default")

    def test_customer_package_audit_scans_zip_entries_and_content(self) -> None:
        run_root = self.output_base / "audit"
        (run_root / "deliverables").mkdir(parents=True, exist_ok=True)
        safe = run_root / "deliverables" / "full_report_customer_customer_v1.0.md"
        safe.write_text("# Customer Report\nContains decision trace marker.\n", encoding="utf-8")
        zip_path = run_root / "delivery.zip"
        with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("report_data/review_queue.jsonl", "{}\n")
        audit = build_customer_package_audit(
            run_root=run_root,
            included_files=["deliverables/full_report_customer_customer_v1.0.md"],
            excluded_files=[],
            zip_path=zip_path,
        )
        self.assertEqual(audit["audit_result"], "fail")
        self.assertTrue(any(item["kind"] == "zip_entry" for item in audit["findings"]))
        self.assertTrue(any(item["kind"] == "content" for item in audit["findings"]))

    def test_bundle_application_recorded_by_cli(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.main",
                "--run-id",
                "bundle-record",
                "--output-base",
                str(self.output_base),
                "--customer-bundle",
                str(self.project_root / "configs" / "customer_bundles" / "default_customer_release.yaml"),
                "--preflight-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Preflight complete", result.stdout)
        payload = json.loads((self.output_base / "bundle-record" / "report_data" / "applied_bundle_config.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["effective"]["deliverable_profile"], "customer_pack")
        self.assertIn("package_policy", payload["effective"])

    def test_onboarding_checklist_and_archive_only_manifest_extended(self) -> None:
        output_root = self.output_base / "archive-run"
        run_pipeline(
            run_id="archive-run",
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
            execution_options={
                "run_id": "archive-run",
                "compare_to_run": "baseline-run",
                "real_burp_dir": str(self.real_root / "burp"),
                "real_nuclei_dir": str(self.real_root / "nuclei"),
                "real_httpx_dir": str(self.real_root / "httpx"),
                "real_manual_dir": str(self.real_root / "manual"),
                "override_file": "override.yaml",
                "suppression_file": "suppression.yaml",
                "review_resolution_file": "review.yaml",
                "require_pptx": False,
            },
            document_meta={"project_name": "Phase11", "client_name": "Client", "report_version": "v11.0"},
        )
        checklist = (output_root / "deliverables" / "real_data_onboarding_checklist.md").read_text(encoding="utf-8")
        archive_manifest = json.loads((output_root / "report_data" / "archive_only_manifest.json").read_text(encoding="utf-8"))
        self.assertIn("real_burp_dir", checklist)
        self.assertEqual(archive_manifest["source_run_id"], "baseline-run")
        self.assertIn("skipped_customer_outputs", archive_manifest)


if __name__ == "__main__":
    unittest.main()
