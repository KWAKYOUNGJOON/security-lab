from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from vuln_pipeline.report import build_git_change_manifest, build_release_readiness_summary, render_commit_prep_summary


class Phase12FeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.output_base = Path(tempfile.mkdtemp(prefix="vuln-pipeline-phase12-"))

    def tearDown(self) -> None:
        for child in self.output_base.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(self.output_base.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        if self.output_base.exists():
            self.output_base.rmdir()

    def test_real_input_missing_creates_blocked_document(self) -> None:
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.main",
                "--run-id",
                "phase12-blocked",
                "--output-base",
                str(self.output_base),
                "--auto-select-real-inputs",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        blocked = self.output_base / "phase12-blocked" / "deliverables" / "real_rehearsal_blocked.md"
        self.assertTrue(blocked.exists())
        self.assertIn("Real Rehearsal Blocked", blocked.read_text(encoding="utf-8"))

    def test_commit_manifest_generation(self) -> None:
        manifest = build_git_change_manifest(
            [
                " M README.md",
                "?? scripts/run_real_rehearsal.ps1",
                "?? .tmp_run12/output.json",
                " D sitecustomize.py",
            ]
        )
        summary = render_commit_prep_summary(manifest)
        self.assertIn("README.md", manifest["files_to_commit"])
        self.assertIn(".tmp_run12/output.json", manifest["files_to_ignore"])
        self.assertIn("Commit Prep Summary", summary)

    def test_release_readiness_summary_generation(self) -> None:
        summary = build_release_readiness_summary(
            baseline_run_id="phase12-real-rehearsal",
            rehearsal_performed=False,
            preflight={
                "manual_sources_ready": False,
                "manual_inputs": {
                    "override_file": {"manual_source": "legacy_default", "effective_path": "legacy/override.yaml"},
                },
            },
            readiness=None,
            submission_gate=None,
            privacy_audit=None,
            pptx_capability={"status": "warning"},
            final_delivery_manifest=None,
            blockers=["real scan inputs are not ready"],
        )
        self.assertIn("phase12-real-rehearsal", summary)
        self.assertIn("real scan inputs are not ready", summary)
        self.assertIn("manual_source=`legacy_default`", summary)

    def test_real_input_readiness_checker_reports_phase12_blockers(self) -> None:
        workspace_root = self.output_base / "workspace"
        app_root = workspace_root / "app" / "vuln-pipeline"
        (app_root / "configs" / "customer_bundles").mkdir(parents=True)
        (app_root / "configs" / "branding").mkdir(parents=True)
        (app_root / "configs" / "readiness").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "burp").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "nuclei").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "httpx").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "manual").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "real" / "burp").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "real" / "nuclei").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "real" / "httpx").mkdir(parents=True)
        (workspace_root / "data" / "inputs" / "real" / "manual").mkdir(parents=True)

        (app_root / "configs" / "customer_bundles" / "default_customer_release.yaml").write_text(
            "report_template: default_customer\n",
            encoding="utf-8",
        )
        (app_root / "configs" / "branding" / "customer_branding.yaml").write_text("client_name: Test\n", encoding="utf-8")
        (app_root / "configs" / "readiness" / "customer_release.yaml").write_text("override_required: true\n", encoding="utf-8")

        (workspace_root / "data" / "inputs" / "burp" / "burp_sample.xml").write_text("<issues><issue></issue></issues>", encoding="utf-8")
        (workspace_root / "data" / "inputs" / "nuclei" / "nuclei_sample.jsonl").write_text(
            '{"template-id":"x","info":{"name":"n","severity":"low"}}\n',
            encoding="utf-8",
        )
        (workspace_root / "data" / "inputs" / "httpx" / "httpx_sample.jsonl").write_text(
            '{"input":"https://example.com","status-code":200}\n',
            encoding="utf-8",
        )
        (workspace_root / "data" / "inputs" / "manual" / "sample_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (workspace_root / "data" / "inputs" / "manual" / "suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (workspace_root / "data" / "inputs" / "manual" / "review_resolution.yaml").write_text(
            "review_resolutions: []\n",
            encoding="utf-8",
        )
        for tool in ("burp", "nuclei", "httpx", "manual"):
            (workspace_root / "data" / "inputs" / "real" / tool / ".gitkeep").write_text(".\n", encoding="utf-8")

        json_out = self.output_base / "readiness.json"
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.real_input_readiness",
                "--workspace-root",
                str(workspace_root),
                "--json-out",
                str(json_out),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        payload = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "blocked")
        self.assertIn("real scan inputs are not ready", payload["blockers"])
        self.assertIn(
            "override_file: manual source is `legacy_default`; expected `real_explicit` during real rehearsal",
            payload["blockers"],
        )
        self.assertIn(
            "suppression_file: manual source is `legacy_default`; expected `real_explicit` during real rehearsal",
            payload["blockers"],
        )
        self.assertIn(
            "review_resolution_file: manual source is `legacy_default`; expected `real_explicit` during real rehearsal",
            payload["blockers"],
        )
        self.assertTrue((json_out.parent / "live_scan_inventory.json").exists())

    def test_manual_bootstrap_creates_safe_working_drafts(self) -> None:
        workspace_root = self.project_root.parents[1]
        review_queue = self.output_base / "review_queue.jsonl"
        output_dir = self.output_base / "manual-drafts"
        review_queue.write_text(
            json.dumps(
                {
                    "issue_id": "I-1000",
                    "finding_ids": ["F-1000"],
                    "priority_band": "P1",
                    "review_reason": ["override_not_applied"],
                    "recommended_action": "Validate mapping and update override if needed.",
                    "host": "portal.example.com",
                    "path_pattern": "/login",
                    "weakness_family": "Auth",
                    "primary_cwe": "CWE-287",
                    "is_resolved": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.manual_bootstrap",
                "--workspace-root",
                str(workspace_root),
                "--review-queue",
                str(review_queue),
                "--output-dir",
                str(output_dir),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("written_files", run.stdout)
        override_payload = yaml.safe_load((output_dir / "override_working.yaml").read_text(encoding="utf-8"))
        suppression_payload = yaml.safe_load((output_dir / "suppression_working.yaml").read_text(encoding="utf-8"))
        resolution_payload = yaml.safe_load((output_dir / "review_resolution_working.yaml").read_text(encoding="utf-8"))
        self.assertEqual(override_payload["overrides"], [])
        self.assertEqual(suppression_payload["suppressions"], [])
        self.assertEqual(resolution_payload["review_resolutions"], [])
        self.assertEqual(len(override_payload["draft_candidates"]), 1)
        self.assertEqual(len(suppression_payload["draft_candidates"]), 1)
        self.assertEqual(len(resolution_payload["draft_candidates"]), 1)
        self.assertEqual(
            override_payload["draft_candidates"][0]["triage_hint"]["suggested_action_bucket"],
            "needs_override_review",
        )
        self.assertTrue((output_dir / "bootstrap_worklist.md").exists())

    def test_phase12_workspace_bootstrap_creates_non_live_structure_and_manifest(self) -> None:
        operator_workspace = self.output_base / "operator-workspace"
        live_root = self.output_base / "live-root"
        live_manual_dir = live_root / "manual"
        live_manual_dir.mkdir(parents=True)
        sentinel = live_manual_dir / "customer_override.yaml"
        sentinel.write_text("overrides: []\n", encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_operator_workspace",
                "bootstrap",
                "--workspace-root",
                str(operator_workspace),
                "--live-root",
                str(live_root),
                "--live-manual-dir",
                str(live_manual_dir),
                "--run-id",
                "phase12-bootstrap-smoke",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((operator_workspace / "phase12_workspace_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "bootstrapped")
        self.assertTrue((operator_workspace / "incoming" / "burp").exists())
        self.assertTrue((operator_workspace / "incoming" / "nuclei").exists())
        self.assertTrue((operator_workspace / "incoming" / "httpx").exists())
        self.assertTrue((operator_workspace / "manual-drafts").exists())
        self.assertTrue((operator_workspace / "phase12_workspace_manifest.md").exists())
        self.assertIn("empty", manifest["seed_mode"])
        self.assertEqual("overrides: []\n", sentinel.read_text(encoding="utf-8"))

    def test_phase12_workspace_bootstrap_seed_from_templates_creates_safe_working_files(self) -> None:
        operator_workspace = self.output_base / "template-workspace"
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_operator_workspace",
                "bootstrap",
                "--workspace-root",
                str(operator_workspace),
                "--seed-from-templates",
                "--run-id",
                "phase12-template-seed",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        override_payload = yaml.safe_load((operator_workspace / "manual-drafts" / "override_working.yaml").read_text(encoding="utf-8"))
        suppression_payload = yaml.safe_load((operator_workspace / "manual-drafts" / "suppression_working.yaml").read_text(encoding="utf-8"))
        resolution_payload = yaml.safe_load((operator_workspace / "manual-drafts" / "review_resolution_working.yaml").read_text(encoding="utf-8"))
        self.assertEqual(override_payload["overrides"], [])
        self.assertEqual(suppression_payload["suppressions"], [])
        self.assertEqual(resolution_payload["review_resolutions"], [])
        self.assertEqual(override_payload["draft_candidates"], [])
        self.assertEqual(suppression_payload["draft_candidates"], [])
        self.assertEqual(resolution_payload["draft_candidates"], [])

    def test_phase12_workspace_bootstrap_seed_from_run_root_reuses_manual_bootstrap(self) -> None:
        operator_workspace = self.output_base / "run-root-workspace"
        source_run_root = self.output_base / "source-run"
        report_data = source_run_root / "report_data"
        report_data.mkdir(parents=True)
        (report_data / "review_queue.jsonl").write_text(
            json.dumps(
                {
                    "issue_id": "I-2000",
                    "finding_ids": ["F-2000"],
                    "priority_band": "P1",
                    "review_reason": ["override_not_applied"],
                    "recommended_action": "Move reviewed data into overrides only after approval.",
                    "host": "api.example.com",
                    "path_pattern": "/v1/login",
                    "weakness_family": "Auth",
                    "primary_cwe": "CWE-287",
                    "is_resolved": False,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_operator_workspace",
                "bootstrap",
                "--workspace-root",
                str(operator_workspace),
                "--seed-from-run-root",
                str(source_run_root),
                "--run-id",
                "phase12-run-root-seed",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        override_payload = yaml.safe_load((operator_workspace / "manual-drafts" / "override_working.yaml").read_text(encoding="utf-8"))
        self.assertEqual(len(override_payload["draft_candidates"]), 1)
        self.assertEqual(override_payload["overrides"], [])
        manifest = json.loads((operator_workspace / "phase12_workspace_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["seed_mode"], "from_run_root")

    def test_manual_promotion_plan_only_creates_plan_without_touching_live_files(self) -> None:
        working_dir = self.output_base / "working"
        live_dir = self.output_base / "live"
        output_dir = self.output_base / "promotion-plan"
        working_dir.mkdir()
        live_dir.mkdir()

        (working_dir / "override_working.yaml").write_text(
            yaml.safe_dump(
                {
                    "overrides": [{"issue_id": "I-1", "override_title": "Reviewed title"}],
                    "draft_candidates": [{"issue_id": "I-1"}],
                },
                sort_keys=False,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")
        live_override = live_dir / "customer_override.yaml"
        live_override.write_text("overrides: []\n", encoding="utf-8")
        before_live = live_override.read_text(encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.manual_promotion",
                "--working-dir",
                str(working_dir),
                "--live-manual-dir",
                str(live_dir),
                "--output-dir",
                str(output_dir),
                "--plan-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        plan = json.loads((output_dir / "manual_promotion_plan.json").read_text(encoding="utf-8"))
        self.assertIn(plan["status"], {"ready_for_review", "ready_to_apply"})
        self.assertTrue((output_dir / "manual_promotion_plan.md").exists())
        self.assertTrue((output_dir / "customer_override_candidate.yaml").exists())
        self.assertEqual(before_live, live_override.read_text(encoding="utf-8"))

    def test_manual_promotion_apply_writes_backup_and_receipt(self) -> None:
        working_dir = self.output_base / "working"
        live_dir = self.output_base / "live"
        output_dir = self.output_base / "promotion-apply"
        working_dir.mkdir()
        live_dir.mkdir()

        (working_dir / "override_working.yaml").write_text(
            yaml.safe_dump({"overrides": [{"issue_id": "I-9", "override_title": "Promoted"}], "draft_candidates": []}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")
        live_override = live_dir / "customer_override.yaml"
        live_override.write_text("overrides: []\n", encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.manual_promotion",
                "--working-dir",
                str(working_dir),
                "--live-manual-dir",
                str(live_dir),
                "--output-dir",
                str(output_dir),
                "--apply",
                "--overwrite",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        receipt = json.loads((output_dir / "manual_promotion_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "applied")
        self.assertTrue((output_dir / "backups").exists())
        self.assertTrue(any((output_dir / "backups").iterdir()))
        promoted = yaml.safe_load(live_override.read_text(encoding="utf-8"))
        self.assertEqual(promoted["overrides"][0]["issue_id"], "I-9")

    def test_manual_promotion_blocks_apply_when_only_draft_candidates_exist(self) -> None:
        working_dir = self.output_base / "working"
        live_dir = self.output_base / "live"
        output_dir = self.output_base / "promotion-blocked"
        working_dir.mkdir()
        live_dir.mkdir()
        (working_dir / "override_working.yaml").write_text("overrides: []\ndraft_candidates:\n  - issue_id: I-2\n", encoding="utf-8")
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.manual_promotion",
                "--working-dir",
                str(working_dir),
                "--live-manual-dir",
                str(live_dir),
                "--output-dir",
                str(output_dir),
                "--apply",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        plan = json.loads((output_dir / "manual_promotion_plan.json").read_text(encoding="utf-8"))
        self.assertIn(plan["status"], {"human_selection_required", "ready_for_review"})
        self.assertFalse((output_dir / "manual_promotion_receipt.json").exists())

    def test_scan_input_promotion_plan_mode_reports_inventory_without_touching_live(self) -> None:
        incoming_root = self.output_base / "incoming"
        live_root = self.output_base / "live"
        output_dir = self.output_base / "scan-plan"
        for tool in ("burp", "nuclei", "httpx"):
            (incoming_root / tool).mkdir(parents=True)
            (live_root / tool).mkdir(parents=True)
        burp_live = live_root / "burp" / "existing.xml"
        burp_live.write_text("<issues>" + ("A" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "burp" / "burp-20260316.xml").write_text("<issues>" + ("B" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")
        before_live = burp_live.read_text(encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(output_dir),
                "--plan-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        plan = json.loads((output_dir / "scan_input_promotion_plan.json").read_text(encoding="utf-8"))
        self.assertIn(plan["status"], {"ready_for_review", "ready_to_apply"})
        self.assertTrue((output_dir / "scan_input_promotion_plan.md").exists())
        self.assertTrue((output_dir / "live_scan_inventory.json").exists())
        self.assertEqual(plan["tools"]["burp"]["selected"]["source_path"], str(incoming_root / "burp" / "burp-20260316.xml"))
        self.assertTrue(plan["tools"]["burp"]["archive_plan"])
        self.assertEqual(before_live, burp_live.read_text(encoding="utf-8"))

    def test_scan_input_promotion_requires_naming_decision_for_excluded_basename(self) -> None:
        incoming_root = self.output_base / "incoming"
        live_root = self.output_base / "live"
        output_dir = self.output_base / "scan-unsafe"
        for tool in ("burp", "nuclei", "httpx"):
            (incoming_root / tool).mkdir(parents=True)
            (live_root / tool).mkdir(parents=True)
        unsafe_file = incoming_root / "burp" / "burp_sample.xml"
        unsafe_file.write_text("<issues>" + ("C" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")

        plan_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(output_dir),
                "--plan-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(plan_run.returncode, 0)
        plan = json.loads((output_dir / "scan_input_promotion_plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["status"], "blocked")
        self.assertTrue(plan["tools"]["burp"]["selected"]["naming_decision_required"] or any("naming decision required" in item for item in plan["blockers"]))

        apply_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(output_dir),
                "--apply",
                "--overwrite",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(apply_run.returncode, 0)
        self.assertFalse((output_dir / "scan_input_promotion_receipt.json").exists())

    def test_scan_input_promotion_apply_archives_previous_live_and_updates_inventory(self) -> None:
        incoming_root = self.output_base / "incoming"
        live_root = self.output_base / "live"
        output_dir = self.output_base / "scan-apply"
        archive_dir = self.output_base / "scan-archive"
        for tool in ("burp", "nuclei", "httpx"):
            (incoming_root / tool).mkdir(parents=True)
            (live_root / tool).mkdir(parents=True)
        (live_root / "burp" / "old-burp.xml").write_text("<issues>" + ("D" * 260) + "</issues>", encoding="utf-8")
        (live_root / "burp" / "older-burp.xml").write_text("<issues>" + ("E" * 260) + "</issues>", encoding="utf-8")
        (live_root / "nuclei" / "old-nuclei.jsonl").write_text('{"info":{"name":"old"}}' + (" " * 140), encoding="utf-8")
        (live_root / "httpx" / "old-httpx.jsonl").write_text('{"url":"https://old"}' + (" " * 140), encoding="utf-8")
        (incoming_root / "burp" / "burp-20260316.xml").write_text("<issues>" + ("F" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"new"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://new"}' + (" " * 140), encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(output_dir),
                "--archive-dir",
                str(archive_dir),
                "--apply",
                "--overwrite",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        receipt = json.loads((output_dir / "scan_input_promotion_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "applied")
        self.assertTrue(any(archive_dir.rglob("*.*")))
        self.assertEqual(len(list((live_root / "burp").glob("*"))), 1)
        inventory = json.loads((output_dir / "live_scan_inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(inventory["tools"]["burp"]["eligible_file_count"], 1)
        self.assertTrue(inventory["tools"]["burp"]["active_file"].endswith("burp-20260316.xml"))

    def test_scan_input_promotion_blocks_ambiguous_candidates_without_explicit_or_auto_pick(self) -> None:
        incoming_root = self.output_base / "incoming"
        live_root = self.output_base / "live"
        output_dir = self.output_base / "scan-ambiguous"
        for tool in ("burp", "nuclei", "httpx"):
            (incoming_root / tool).mkdir(parents=True)
            (live_root / tool).mkdir(parents=True)
        (incoming_root / "burp" / "burp-1.xml").write_text("<issues>" + ("G" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "burp" / "burp-2.xml").write_text("<issues>" + ("H" * 261) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")

        blocked_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(output_dir),
                "--plan-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(blocked_run.returncode, 0)
        blocked_plan = json.loads((output_dir / "scan_input_promotion_plan.json").read_text(encoding="utf-8"))
        self.assertEqual(blocked_plan["status"], "blocked")
        self.assertEqual(len(blocked_plan["tools"]["burp"]["selected"]["ambiguous_candidates"]), 2)

        explicit_output = self.output_base / "scan-explicit"
        explicit_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--incoming-burp",
                str(incoming_root / "burp" / "burp-1.xml"),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(explicit_output),
                "--plan-only",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(explicit_run.returncode, 0, explicit_run.stderr)

        auto_output = self.output_base / "scan-auto"
        auto_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.scan_input_promotion",
                "--incoming-root",
                str(incoming_root),
                "--live-root",
                str(live_root),
                "--output-dir",
                str(auto_output),
                "--plan-only",
                "--allow-auto-pick",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(auto_run.returncode, 0, auto_run.stderr)

    def test_post_run_triage_reports_success_run(self) -> None:
        workspace_root = self.output_base / "workspace"
        run_root = workspace_root / "outputs" / "runs" / "triage-success"
        report_data = run_root / "report_data"
        delivery_dir = run_root / "delivery"
        real_manual_dir = workspace_root / "data" / "inputs" / "real" / "manual"
        report_data.mkdir(parents=True)
        delivery_dir.mkdir(parents=True)
        real_manual_dir.mkdir(parents=True)

        (report_data / "release_readiness.json").write_text(
            json.dumps({"status": "ready", "checks": [], "blocker_summary": []}),
            encoding="utf-8",
        )
        (report_data / "submission_gate.json").write_text(
            json.dumps({"status": "pass", "checks": [], "blocking_reasons": [], "warning_reasons": []}),
            encoding="utf-8",
        )
        (report_data / "review_closure_status.json").write_text(
            json.dumps({"unresolved_review_items": 0}),
            encoding="utf-8",
        )
        (report_data / "real_input_selection.json").write_text(json.dumps({"status": "selected"}), encoding="utf-8")
        (report_data / "review_queue.jsonl").write_text(
            json.dumps({"issue_id": "I-1", "is_resolved": True}) + "\n",
            encoding="utf-8",
        )
        (delivery_dir / "final_delivery_manifest.json").write_text(
            json.dumps({"final_ready": True, "blocking_reasons": []}),
            encoding="utf-8",
        )
        (delivery_dir / "customer_submission_v1.0.zip").write_text("zip", encoding="utf-8")
        (delivery_dir / "internal_archive_v1.0.zip").write_text("zip", encoding="utf-8")
        (real_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (real_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (real_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.post_run_triage",
                "--run-root",
                str(run_root),
                "--manual-dir",
                str(real_manual_dir),
                "--output-dir",
                str(report_data),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        triage = json.loads((report_data / "post_run_triage.json").read_text(encoding="utf-8"))
        validation = json.loads((report_data / "manual_validation.json").read_text(encoding="utf-8"))
        self.assertEqual(triage["rollup_status"], "pass")
        self.assertTrue(triage["state_flags"]["final_ready"])
        self.assertEqual(triage["worklist"]["unresolved_count"], 0)
        self.assertEqual(validation["status"], "valid")
        self.assertTrue(validation["rerun_live_context"]["format_valid"])

    def test_post_run_triage_detects_blocked_run_and_malformed_manual(self) -> None:
        workspace_root = self.output_base / "workspace"
        run_root = workspace_root / "outputs" / "runs" / "triage-blocked"
        report_data = run_root / "report_data"
        deliverables_dir = run_root / "deliverables"
        real_manual_dir = workspace_root / "data" / "inputs" / "real" / "manual"
        report_data.mkdir(parents=True)
        deliverables_dir.mkdir(parents=True)
        real_manual_dir.mkdir(parents=True)

        (report_data / "input_preflight.json").write_text(
            json.dumps({"status": "blocked", "blockers": ["real scan inputs are not ready"]}),
            encoding="utf-8",
        )
        (report_data / "real_input_selection.json").write_text(json.dumps({"status": "incomplete"}), encoding="utf-8")
        (deliverables_dir / "real_rehearsal_blocked.md").write_text(
            "# Real Rehearsal Blocked\n\n- reason: `blocked`\n",
            encoding="utf-8",
        )
        (deliverables_dir / "release_readiness_summary.md").write_text(
            "# Release Readiness Summary\n\n- readiness_status: `not_generated`\n",
            encoding="utf-8",
        )
        (real_manual_dir / "customer_override.yaml").write_text("overrides: [\n", encoding="utf-8")
        (real_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (real_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.post_run_triage",
                "--run-root",
                str(run_root),
                "--manual-dir",
                str(real_manual_dir),
                "--output-dir",
                str(report_data),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        triage = json.loads((report_data / "post_run_triage.json").read_text(encoding="utf-8"))
        validation = json.loads((report_data / "manual_validation.json").read_text(encoding="utf-8"))
        self.assertEqual(triage["rollup_status"], "blocked")
        self.assertIn("release_readiness", triage["hard_facts"]["missing_artifacts"])
        override_validation = validation["rerun_live_context"]["files"]["override_file"]
        self.assertFalse(validation["rerun_live_context"]["format_valid"])
        self.assertTrue(any("Parse error" in item for item in override_validation["issues"]))

    def test_rerun_comparison_summarizes_baseline_vs_blocked(self) -> None:
        workspace_root = self.output_base / "workspace"
        current_run_root = workspace_root / "outputs" / "runs" / "current"
        previous_run_root = workspace_root / "outputs" / "runs" / "previous"
        live_manual_dir = workspace_root / "data" / "inputs" / "real" / "manual"
        live_manual_dir.mkdir(parents=True)
        self._write_success_run(current_run_root, live_manual_dir)
        self._write_blocked_run(previous_run_root, live_manual_dir)

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.rerun_comparison",
                "--current-run-root",
                str(current_run_root),
                "--previous-run-root",
                str(previous_run_root),
                "--manual-dir",
                str(live_manual_dir),
                "--output-dir",
                str(current_run_root / "report_data"),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        comparison = json.loads((current_run_root / "report_data" / "rerun_comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(comparison["inference"]["summary"], "improved")
        self.assertTrue(comparison["hard_facts"]["final_ready"]["changed"])
        self.assertTrue((current_run_root / "report_data" / "rerun_comparison.md").exists())

    def test_run_real_rehearsal_wrapper_emits_triage_artifacts_when_blocked(self) -> None:
        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_real_rehearsal.ps1"),
                "-RunId",
                "phase12-wrapper-smoke",
                "-OutputBase",
                str(self.output_base),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        report_data = self.output_base / "phase12-wrapper-smoke" / "report_data"
        self.assertTrue((report_data / "real_input_readiness.json").exists())
        self.assertTrue((report_data / "post_run_triage.json").exists())
        self.assertTrue((report_data / "manual_validation.json").exists())

    def test_run_phase12_iteration_wrapper_can_bootstrap_workspace_and_stop(self) -> None:
        operator_workspace = self.output_base / "wrapper-bootstrap"
        output_base = self.output_base / "wrapper-bootstrap-runs"

        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_phase12_iteration.ps1"),
                "-RunId",
                "phase12-bootstrap-only",
                "-WorkspaceRoot",
                str(operator_workspace),
                "-InitWorkspace",
                "-SeedManualDraftsFromTemplates",
                "-StopAfterBootstrap",
                "-OutputBase",
                str(output_base),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue((operator_workspace / "manual-drafts" / "override_working.yaml").exists())
        self.assertTrue((operator_workspace / "phase12_workspace_manifest.json").exists())
        operator_case = json.loads(
            (output_base / "phase12-bootstrap-only" / "report_data" / "phase12_operator_case.json").read_text(encoding="utf-8")
        )
        self.assertEqual(operator_case["hard_facts"]["case_phase"], "post-bootstrap")

    def test_run_phase12_iteration_wrapper_missing_working_dir_emits_operator_case_and_stub_plan(self) -> None:
        live_manual_dir = self.output_base / "live-manual"
        live_root = self.output_base / "live-root"
        previous_run_root = self.output_base / "previous-run"
        output_base = self.output_base / "wrapper-missing-working"
        for tool in ("burp", "nuclei", "httpx"):
            (live_root / tool).mkdir(parents=True)
        live_manual_dir.mkdir()
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")
        self._write_blocked_run(previous_run_root, live_manual_dir)

        missing_working = self.output_base / "missing-manual-drafts"
        incoming_root = self.output_base / "incoming-root"
        for tool in ("burp", "nuclei", "httpx"):
            (incoming_root / tool).mkdir(parents=True)

        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_phase12_iteration.ps1"),
                "-RunId",
                "phase12-missing-working",
                "-WorkingDir",
                str(missing_working),
                "-IncomingScanRoot",
                str(incoming_root),
                "-LiveManualDir",
                str(live_manual_dir),
                "-LiveRoot",
                str(live_root),
                "-OutputBase",
                str(output_base),
                "-PreviousRunRoot",
                str(previous_run_root),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        report_data = output_base / "phase12-missing-working" / "report_data"
        promotion_plan = json.loads((report_data / "manual_promotion" / "manual_promotion_plan.json").read_text(encoding="utf-8"))
        operator_case = json.loads((report_data / "phase12_operator_case.json").read_text(encoding="utf-8"))
        self.assertEqual(promotion_plan["status"], "blocked")
        self.assertTrue((report_data / "post_run_triage.json").exists())
        self.assertTrue((report_data / "rerun_comparison.json").exists())
        self.assertIn("manual working drafts are missing", "\n".join(operator_case["suggestions"]["operator_confirmation_needed"]))
        self.assertTrue(operator_case["suggestions"]["exact_next_commands"])

    def test_run_phase12_iteration_wrapper_plan_only_emits_promotion_and_comparison_artifacts(self) -> None:
        live_manual_dir = self.output_base / "live-manual"
        live_root = self.output_base / "live-root"
        incoming_root = self.output_base / "incoming-root"
        working_dir = self.output_base / "working"
        previous_run_root = self.output_base / "previous-run"
        output_base = self.output_base / "wrapper-runs"
        live_manual_dir.mkdir()
        for tool in ("burp", "nuclei", "httpx"):
            (live_root / tool).mkdir(parents=True)
            (incoming_root / tool).mkdir(parents=True)
        working_dir.mkdir()

        (working_dir / "override_working.yaml").write_text("overrides: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")
        (incoming_root / "burp" / "burp-20260316.xml").write_text("<issues>" + ("I" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")
        self._write_blocked_run(previous_run_root, live_manual_dir)

        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_phase12_iteration.ps1"),
                "-RunId",
                "phase12-iteration-smoke",
                "-WorkingDir",
                str(working_dir),
                "-LiveManualDir",
                str(live_manual_dir),
                "-LiveRoot",
                str(live_root),
                "-IncomingScanRoot",
                str(incoming_root),
                "-OutputBase",
                str(output_base),
                "-PreviousRunRoot",
                str(previous_run_root),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        report_data = output_base / "phase12-iteration-smoke" / "report_data"
        self.assertTrue((report_data / "scan_promotion" / "scan_input_promotion_plan.json").exists())
        self.assertTrue((report_data / "scan_promotion" / "live_scan_inventory.json").exists())
        self.assertTrue((report_data / "manual_promotion" / "manual_promotion_plan.json").exists())
        self.assertTrue((report_data / "post_run_triage.json").exists())
        self.assertTrue((report_data / "rerun_comparison.json").exists())
        self.assertTrue((report_data / "phase12_evidence_pack.json").exists())

    def test_phase12_signoff_review_creates_review_and_intent_template(self) -> None:
        workspace_root = self.output_base / "operator-workspace"
        report_data = self.output_base / "runs" / "phase12-signoff" / "report_data"
        self._write_phase12_workspace_manifest(workspace_root)
        self._write_phase12_operator_case(report_data, workspace_root=workspace_root)
        self._write_scan_plan(report_data / "scan_promotion", ambiguous=True, naming_required=True)
        self._write_manual_plan(report_data / "manual_promotion", status="human_selection_required", actionable_count=0, draft_candidate_count=2)

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_apply_signoff",
                "review",
                "--workspace-root",
                str(workspace_root),
                "--run-id",
                "phase12-signoff",
                "--output-dir",
                str(report_data),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        review = json.loads((report_data / "phase12_signoff_review.json").read_text(encoding="utf-8"))
        intent = json.loads((report_data / "phase12_apply_intent.template.json").read_text(encoding="utf-8"))
        self.assertEqual(review["status"], "not_ready_for_apply")
        self.assertTrue(review["hard_facts"]["ambiguous_candidate_present"])
        self.assertTrue(review["hard_facts"]["naming_decision_required_present"])
        self.assertIn("operator-confirmation-needed", "\n".join(review["blocking_items"]))
        self.assertFalse(intent["apply_scan_promotion"])
        self.assertFalse(intent["acknowledgements"]["review_pack_read"])
        self.assertTrue((report_data / "phase12_signoff_review.md").exists())

    def test_phase12_signoff_review_missing_plan_is_not_ready(self) -> None:
        workspace_root = self.output_base / "operator-workspace-missing"
        report_data = self.output_base / "runs" / "phase12-signoff-missing" / "report_data"
        self._write_phase12_workspace_manifest(workspace_root)
        self._write_phase12_operator_case(report_data, workspace_root=workspace_root)

        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_apply_signoff",
                "review",
                "--workspace-root",
                str(workspace_root),
                "--run-id",
                "phase12-signoff-missing",
                "--output-dir",
                str(report_data),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        review = json.loads((report_data / "phase12_signoff_review.json").read_text(encoding="utf-8"))
        self.assertEqual(review["status"], "not_ready_for_apply")
        self.assertTrue(any("scan_input_promotion_plan.json" in item for item in review["blocking_items"]))

    def test_run_phase12_iteration_wrapper_blocks_apply_without_intent_and_emits_signoff_and_evidence(self) -> None:
        live_manual_dir = self.output_base / "live-manual-intentless"
        live_root = self.output_base / "live-root-intentless"
        incoming_root = self.output_base / "incoming-intentless"
        working_dir = self.output_base / "working-intentless"
        previous_run_root = self.output_base / "previous-intentless"
        output_base = self.output_base / "wrapper-intentless-runs"
        live_manual_dir.mkdir()
        for tool in ("burp", "nuclei", "httpx"):
            (live_root / tool).mkdir(parents=True)
            (incoming_root / tool).mkdir(parents=True)
        working_dir.mkdir()

        (working_dir / "override_working.yaml").write_text("overrides: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")
        (incoming_root / "burp" / "burp-20260316.xml").write_text("<issues>" + ("I" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")
        self._write_blocked_run(previous_run_root, live_manual_dir)

        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_phase12_iteration.ps1"),
                "-RunId",
                "phase12-intentless",
                "-WorkingDir",
                str(working_dir),
                "-LiveManualDir",
                str(live_manual_dir),
                "-LiveRoot",
                str(live_root),
                "-IncomingScanRoot",
                str(incoming_root),
                "-OutputBase",
                str(output_base),
                "-PreviousRunRoot",
                str(previous_run_root),
                "-ApplyScanPromotion",
                "-ApplyPromotion",
                "-Overwrite",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        report_data = output_base / "phase12-intentless" / "report_data"
        self.assertTrue((report_data / "phase12_signoff_review.json").exists())
        self.assertTrue((report_data / "phase12_evidence_pack.json").exists())
        self.assertFalse((report_data / "scan_promotion" / "scan_input_promotion_receipt.json").exists())
        self.assertFalse((report_data / "manual_promotion" / "manual_promotion_receipt.json").exists())

    def test_run_phase12_iteration_wrapper_blocks_stale_intent(self) -> None:
        live_manual_dir = self.output_base / "live-manual-stale"
        live_root = self.output_base / "live-root-stale"
        incoming_root = self.output_base / "incoming-stale"
        working_dir = self.output_base / "working-stale"
        previous_run_root = self.output_base / "previous-stale"
        output_base = self.output_base / "wrapper-stale-runs"
        live_manual_dir.mkdir()
        for tool in ("burp", "nuclei", "httpx"):
            (live_root / tool).mkdir(parents=True)
            (incoming_root / tool).mkdir(parents=True)
        working_dir.mkdir()

        (working_dir / "override_working.yaml").write_text("overrides: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "suppression_working.yaml").write_text("suppressions: []\ndraft_candidates: []\n", encoding="utf-8")
        (working_dir / "review_resolution_working.yaml").write_text("review_resolutions: []\ndraft_candidates: []\n", encoding="utf-8")
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")
        (incoming_root / "burp" / "burp-20260316.xml").write_text("<issues>" + ("I" * 260) + "</issues>", encoding="utf-8")
        (incoming_root / "nuclei" / "nuclei-20260316.jsonl").write_text('{"info":{"name":"x"}}' + (" " * 140), encoding="utf-8")
        (incoming_root / "httpx" / "httpx-20260316.jsonl").write_text('{"url":"https://a"}' + (" " * 140), encoding="utf-8")
        self._write_blocked_run(previous_run_root, live_manual_dir)

        intent_file = self.output_base / "stale-intent.json"
        intent_file.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": "phase12-stale-intent",
                    "apply_scan_promotion": True,
                    "apply_manual_promotion": True,
                    "review_status_seen": "review_required",
                    "reviewed_by": "qa",
                    "reviewed_at": "2026-03-16T00:00:00Z",
                    "notes": "stale",
                    "expected_workspace_manifest_hash": "stale",
                    "expected_scan_plan_hash": "stale",
                    "expected_manual_plan_hash": "stale",
                    "expected_operator_case_hash": "stale",
                    "expected_live_scan_inventory_hash": "stale",
                    "unresolved_items": [],
                    "review_items_seen": [],
                    "acknowledgements": {
                        "review_pack_read": True,
                        "live_apply_is_explicit": True,
                        "non_live_workspace_vs_live_dir_checked": True,
                        "draft_candidates_not_auto_approved": True,
                    },
                }
            ),
            encoding="utf-8",
        )

        run = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.project_root / "scripts" / "run_phase12_iteration.ps1"),
                "-RunId",
                "phase12-stale-intent",
                "-WorkingDir",
                str(working_dir),
                "-LiveManualDir",
                str(live_manual_dir),
                "-LiveRoot",
                str(live_root),
                "-IncomingScanRoot",
                str(incoming_root),
                "-OutputBase",
                str(output_base),
                "-PreviousRunRoot",
                str(previous_run_root),
                "-IntentFile",
                str(intent_file),
                "-ApplyScanPromotion",
                "-ApplyPromotion",
                "-Overwrite",
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(run.returncode, 0)
        validation = json.loads(
            (output_base / "phase12-stale-intent" / "report_data" / "phase12_apply_intent_validation.json").read_text(encoding="utf-8")
        )
        self.assertEqual(validation["status"], "invalid")
        self.assertTrue(any("stale" in item for item in validation["block_reasons"]))
        self.assertFalse((output_base / "phase12-stale-intent" / "report_data" / "scan_promotion" / "scan_input_promotion_receipt.json").exists())

    def test_phase12_evidence_pack_summarizes_existing_runs(self) -> None:
        baseline_run = self.project_root.parents[1] / "outputs" / "runs" / "phase9-final-demo-v9"
        blocked_run = self.project_root.parents[1] / "outputs" / "runs" / "phase12-real-rehearsal"
        if not baseline_run.exists() or not blocked_run.exists():
            self.skipTest("existing phase9/phase12 runs are not available")

        baseline_out = self.output_base / "baseline-evidence"
        blocked_out = self.output_base / "blocked-evidence"
        baseline = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_evidence_pack",
                "--run-root",
                str(baseline_run),
                "--output-dir",
                str(baseline_out),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        blocked = subprocess.run(
            [
                sys.executable,
                "-m",
                "vuln_pipeline.cli.phase12_evidence_pack",
                "--run-root",
                str(blocked_run),
                "--previous-run-root",
                str(baseline_run),
                "--output-dir",
                str(blocked_out),
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertEqual(blocked.returncode, 0, blocked.stderr)
        baseline_pack = json.loads((baseline_out / "phase12_evidence_pack.json").read_text(encoding="utf-8"))
        blocked_pack = json.loads((blocked_out / "phase12_evidence_pack.json").read_text(encoding="utf-8"))
        self.assertIn("run_root", baseline_pack["hard_facts"])
        self.assertIn("blocked_reason_summary", blocked_pack["hard_facts"])
        self.assertTrue((blocked_out / "phase12_evidence_pack.md").exists())

    def _write_phase12_workspace_manifest(self, workspace_root: Path) -> None:
        (workspace_root / "incoming" / "burp").mkdir(parents=True)
        (workspace_root / "incoming" / "nuclei").mkdir(parents=True)
        (workspace_root / "incoming" / "httpx").mkdir(parents=True)
        (workspace_root / "manual-drafts").mkdir(parents=True)
        (workspace_root / "phase12_workspace_manifest.json").write_text(
            json.dumps(
                {
                    "status": "bootstrapped",
                    "directories": {
                        "incoming_root": str(workspace_root / "incoming"),
                        "manual_drafts": str(workspace_root / "manual-drafts"),
                    },
                }
            ),
            encoding="utf-8",
        )

    def _write_phase12_operator_case(self, report_data: Path, *, workspace_root: Path) -> None:
        report_data.mkdir(parents=True, exist_ok=True)
        (report_data / "phase12_operator_case.json").write_text(
            json.dumps(
                {
                    "status": "captured",
                    "hard_facts": {
                        "workspace_root": str(workspace_root),
                        "working_dir": {"path": str(workspace_root / "manual-drafts"), "exists": True},
                        "incoming_root": {"path": str(workspace_root / "incoming"), "exists": True},
                        "live_root": {"path": str(self.output_base / "live-root"), "exists": True},
                        "live_manual_dir": {"path": str(self.output_base / "live-root" / "manual"), "exists": True},
                        "blocked_reason_summary": [],
                    },
                    "suggestions": {"exact_next_commands": []},
                }
            ),
            encoding="utf-8",
        )

    def _write_scan_plan(self, output_dir: Path, *, ambiguous: bool = False, naming_required: bool = False) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        candidates = [str(output_dir / "incoming-a.xml")]
        if ambiguous:
            candidates.append(str(output_dir / "incoming-b.xml"))
        (output_dir / "scan_input_promotion_plan.json").write_text(
            json.dumps(
                {
                    "status": "blocked" if ambiguous or naming_required else "ready_to_apply",
                    "warnings": [],
                    "tools": {
                        "burp": {
                            "selected": {
                                "ambiguous_candidates": candidates,
                                "naming_decision_required": naming_required,
                            },
                            "blockers": (
                                ["multiple promotion-eligible incoming candidates were found; explicit source or --allow-auto-pick is required"]
                                if ambiguous
                                else []
                            )
                            + (
                                ["naming decision required because the selected incoming basename would be excluded by auto-select"]
                                if naming_required
                                else []
                            ),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (output_dir / "live_scan_inventory.json").write_text(
            json.dumps({"status": "ready", "warnings": [], "blockers": []}),
            encoding="utf-8",
        )

    def _write_manual_plan(
        self,
        output_dir: Path,
        *,
        status: str,
        actionable_count: int,
        draft_candidate_count: int,
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manual_promotion_plan.json").write_text(
            json.dumps(
                {
                    "status": status,
                    "warnings": [],
                    "status_flags": {
                        "has_material_change": actionable_count > 0,
                        "has_human_selection_required": draft_candidate_count > 0 and actionable_count == 0,
                    },
                    "summary": {
                        "actionable_entry_count": actionable_count,
                        "draft_candidate_count": draft_candidate_count,
                    },
                }
            ),
            encoding="utf-8",
        )

    def _write_success_run(self, run_root: Path, live_manual_dir: Path) -> None:
        report_data = run_root / "report_data"
        delivery_dir = run_root / "delivery"
        report_data.mkdir(parents=True)
        delivery_dir.mkdir(parents=True)
        (report_data / "release_readiness.json").write_text(
            json.dumps({"status": "ready", "checks": [], "blocker_summary": []}),
            encoding="utf-8",
        )
        (report_data / "submission_gate.json").write_text(
            json.dumps({"status": "pass", "checks": [], "blocking_reasons": [], "warning_reasons": []}),
            encoding="utf-8",
        )
        (report_data / "review_closure_status.json").write_text(json.dumps({"unresolved_review_items": 0}), encoding="utf-8")
        (report_data / "real_input_selection.json").write_text(json.dumps({"status": "selected"}), encoding="utf-8")
        (report_data / "review_queue.jsonl").write_text(json.dumps({"issue_id": "I-1", "is_resolved": True}) + "\n", encoding="utf-8")
        (delivery_dir / "final_delivery_manifest.json").write_text(
            json.dumps({"final_ready": True, "blocking_reasons": []}),
            encoding="utf-8",
        )
        (delivery_dir / "customer_submission_v1.0.zip").write_text("zip", encoding="utf-8")
        (delivery_dir / "internal_archive_v1.0.zip").write_text("zip", encoding="utf-8")
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")

    def _write_blocked_run(self, run_root: Path, live_manual_dir: Path) -> None:
        report_data = run_root / "report_data"
        deliverables_dir = run_root / "deliverables"
        report_data.mkdir(parents=True)
        deliverables_dir.mkdir(parents=True)
        (report_data / "input_preflight.json").write_text(
            json.dumps({"status": "blocked", "blockers": ["real scan inputs are not ready"]}),
            encoding="utf-8",
        )
        (report_data / "real_input_selection.json").write_text(json.dumps({"status": "incomplete"}), encoding="utf-8")
        (report_data / "review_queue.jsonl").write_text(
            json.dumps({"issue_id": "I-2", "is_resolved": False}) + "\n",
            encoding="utf-8",
        )
        (deliverables_dir / "real_rehearsal_blocked.md").write_text("# Real Rehearsal Blocked\n", encoding="utf-8")
        (deliverables_dir / "release_readiness_summary.md").write_text("# Release Readiness Summary\n", encoding="utf-8")
        (live_manual_dir / "customer_override.yaml").write_text("overrides: []\n", encoding="utf-8")
        (live_manual_dir / "customer_suppressions.yaml").write_text("suppressions: []\n", encoding="utf-8")
        (live_manual_dir / "customer_review_resolution.yaml").write_text("review_resolutions: []\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
