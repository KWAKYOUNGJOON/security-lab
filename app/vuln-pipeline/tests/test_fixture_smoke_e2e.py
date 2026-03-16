from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from vuln_pipeline.pipeline import run_pipeline


pytestmark = [pytest.mark.must_pass, pytest.mark.smoke_e2e]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = json.loads((PROJECT_ROOT / "tests" / "golden" / "smoke_contracts.json").read_text(encoding="utf-8"))


def _run_pipeline(output_root: Path, *, run_id: str, report_version: str, compare_to: Path | None = None, archive_only: bool = False, require_pptx: bool = False, release_candidate: bool = False, finalize_delivery: bool = False) -> None:
    run_pipeline(
        run_id=run_id,
        inputs={
            "burp": [PROJECT_ROOT / "tests" / "fixtures" / "realish" / "burp_complex.xml"],
            "nuclei": [PROJECT_ROOT / "tests" / "fixtures" / "realish" / "nuclei_rich.jsonl"],
            "httpx": [PROJECT_ROOT / "tests" / "fixtures" / "realish" / "httpx_rich.jsonl"],
        },
        output_root=output_root,
        mapping_config=PROJECT_ROOT / "configs" / "mapping_rules.json",
        scoring_config=PROJECT_ROOT / "configs" / "scoring_rules.json",
        override_path=PROJECT_ROOT / "tests" / "fixtures" / "realish" / "override_realish.yaml",
        suppressions_path=PROJECT_ROOT / "tests" / "fixtures" / "realish" / "suppressions.yaml",
        review_resolution_path=PROJECT_ROOT / "tests" / "fixtures" / "realish" / "review_resolution.yaml",
        compare_to_run=compare_to,
        ingest_manifest={"ingested": {"burp": [], "nuclei": [], "httpx": []}, "warnings": []},
        report_profile="customer",
        knowledge_dir=PROJECT_ROOT / "configs" / "knowledge",
        profile_dir=PROJECT_ROOT / "configs" / "report_profiles",
        template_dir=PROJECT_ROOT / "configs" / "report_templates",
        deliverable_profile_dir=PROJECT_ROOT / "configs" / "deliverable_profiles",
        remediation_policy_dir=PROJECT_ROOT / "configs" / "remediation_policy",
        readiness_policy_path=PROJECT_ROOT / "configs" / "readiness" / "customer_release.yaml",
        report_template="default_customer",
        deliverable_profile="customer_pack",
        package_output=True,
        archive_only=archive_only,
        require_pptx=require_pptx,
        release_candidate=release_candidate,
        finalize_delivery=finalize_delivery,
        execution_options={"run_id": run_id, "compare_to_run": "smoke-baseline" if archive_only else None, "require_pptx": require_pptx},
        document_meta={
            "project_name": "Fixture Smoke",
            "client_name": "Fixture Client",
            "engagement_name": "E2E Smoke",
            "analyst_name": "QA",
            "organization_name": "Security Lab",
            "report_version": report_version,
            "delivery_date": "2026-03-16",
            "approver_name": "Fixture Approver",
            "contact_email": "qa@example.com",
        },
    )


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_required_keys(payload: dict, keys: list[str]) -> None:
    missing = [key for key in keys if key not in payload]
    assert not missing, f"missing keys: {missing}"


def _assert_paths_exist(root: Path, relative_paths: list[str]) -> None:
    missing = [path for path in relative_paths if not (root / path).exists()]
    assert not missing, f"missing paths: {missing}"


def _assert_paths_absent(root: Path, relative_paths: list[str]) -> None:
    present = [path for path in relative_paths if (root / path).exists()]
    assert not present, f"unexpected paths: {present}"


def test_happy_path_customer_final_contract(tmp_path: Path) -> None:
    baseline_root = tmp_path / "baseline"
    _run_pipeline(baseline_root, run_id="smoke-baseline", report_version="vsmoke")

    output_root = tmp_path / "happy-path"
    _run_pipeline(
        output_root,
        run_id="smoke-happy-path",
        report_version="vsmoke",
        compare_to=baseline_root,
        release_candidate=True,
        finalize_delivery=True,
    )

    contract = CONTRACTS["happy_path"]
    readiness = _load_json(output_root / "report_data" / "release_readiness.json")
    final_delivery = _load_json(output_root / "delivery" / "final_delivery_manifest.json")
    audit = _load_json(output_root / "report_data" / "customer_package_audit.json")

    _assert_required_keys(readiness, contract["release_readiness_required_keys"])
    _assert_required_keys(final_delivery, contract["final_delivery_required_keys"])
    _assert_required_keys(audit, contract["customer_package_audit_required_keys"])
    _assert_paths_exist(output_root, contract["required_deliverables"])
    _assert_paths_absent(output_root, contract["forbidden_paths"])

    assert readiness["status"] == "ready"
    assert final_delivery["final_ready"] is True
    assert final_delivery["submission_gate"]["status"] in {"pass", "conditional_pass"}
    assert audit["audit_result"] == "pass"


def test_preflight_blocked_contract(tmp_path: Path) -> None:
    run_id = "smoke-preflight-blocked"
    burp_dir = tmp_path / "inputs" / "burp"
    nuclei_dir = tmp_path / "inputs" / "nuclei"
    httpx_dir = tmp_path / "inputs" / "httpx"
    manual_dir = tmp_path / "inputs" / "manual"
    for path in (burp_dir, nuclei_dir, httpx_dir, manual_dir):
        path.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vuln_pipeline.cli.main",
            "--run-id",
            run_id,
            "--output-base",
            str(tmp_path),
            "--burp-dir",
            str(burp_dir),
            "--nuclei-dir",
            str(nuclei_dir),
            "--httpx-dir",
            str(httpx_dir),
            "--override-file",
            str(manual_dir / "missing_override.yaml"),
            "--suppression-file",
            str(manual_dir / "missing_suppression.yaml"),
            "--review-resolution-file",
            str(manual_dir / "missing_review_resolution.yaml"),
            "--customer-bundle",
            str(PROJECT_ROOT / "configs" / "customer_bundles" / "default_customer_release.yaml"),
            "--preflight-only",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    output_root = tmp_path / run_id
    contract = CONTRACTS["preflight_blocked"]
    preflight = _load_json(output_root / "report_data" / "input_preflight.json")

    _assert_required_keys(preflight, contract["preflight_required_keys"])
    _assert_paths_absent(output_root, contract["forbidden_paths"])

    assert "Preflight complete" in result.stdout
    assert preflight["status"] == "blocked"
    assert preflight["blocker_count"] > 0
    assert preflight["selected_run_inputs"] == []


def test_archive_only_contract(tmp_path: Path) -> None:
    output_root = tmp_path / "archive-only"
    _run_pipeline(output_root, run_id="smoke-archive-only", report_version="varchive", archive_only=True)

    contract = CONTRACTS["archive_only"]
    archive_manifest = _load_json(output_root / "report_data" / "archive_only_manifest.json")
    final_delivery = _load_json(output_root / "delivery" / "final_delivery_manifest.json")

    _assert_required_keys(archive_manifest, contract["archive_manifest_required_keys"])
    _assert_paths_exist(output_root, contract["required_paths"])
    _assert_paths_absent(output_root, contract["forbidden_paths"])

    assert archive_manifest["source_run_id"] == "smoke-baseline"
    assert final_delivery["final_ready"] is False


def test_pptx_capability_contract(tmp_path: Path) -> None:
    output_root = tmp_path / "pptx-capability"
    _run_pipeline(
        output_root,
        run_id="smoke-pptx-capability",
        report_version="vpptx",
        require_pptx=True,
        finalize_delivery=True,
    )

    contract = CONTRACTS["pptx_capability"]
    capability = _load_json(output_root / "report_data" / "pptx_capability.json")
    final_delivery = _load_json(output_root / "delivery" / "final_delivery_manifest.json")

    _assert_required_keys(capability, contract["pptx_required_keys"])
    _assert_paths_exist(output_root, contract["required_paths"])

    assert capability["status"] in {"ready", "blocked"}
    assert capability["require_pptx_would_block"] is (not (capability["dependency_found"] and capability["import_check"]))
    assert "PPTX capability" in (output_root / "deliverables" / "final_submission_check.md").read_text(encoding="utf-8")
    if capability["require_pptx_would_block"]:
        assert final_delivery["final_ready"] is False
