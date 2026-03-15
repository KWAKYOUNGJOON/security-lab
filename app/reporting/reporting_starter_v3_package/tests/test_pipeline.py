from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_pipeline_runs_with_samples(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    output_dir = tmp_path / "pipeline"
    command = [
        sys.executable,
        "pipeline.py",
        "--target",
        "https://www.example.org",
        "--author",
        "pytest",
        "--nuclei",
        "sample_nuclei.jsonl",
        "--burp",
        "sample_burp_issues.xml",
        "--ffuf",
        "sample_ffuf.json",
        "--httpx",
        "sample_httpx.jsonl",
        "--nikto",
        "sample_nikto.json",
        "--include-banner",
        "--docx",
        "--output-dir",
        str(output_dir),
    ]
    completed = subprocess.run(command, cwd=root, check=False)
    assert completed.returncode == 0
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.md").exists()
    assert (output_dir / "report.docx").exists()
    assert (output_dir / "deduped_report.json").exists()


def test_pipeline_applies_override_file(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    output_dir = tmp_path / "pipeline_override"
    override_file = tmp_path / "override.json"
    override_file.write_text(
        """
        {
          "findings": [
            {
              "match": {"title": "관리자 또는 인접 경로 노출"},
              "override": {"severity": "high", "manual_verified": true, "notes": "운영자 확인"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    command = [
        sys.executable,
        "pipeline.py",
        "--target",
        "https://www.example.org",
        "--author",
        "pytest",
        "--httpx",
        "sample_httpx.jsonl",
        "--include-banner",
        "--override-file",
        str(override_file),
        "--output-dir",
        str(output_dir),
    ]
    completed = subprocess.run(command, cwd=root, check=False)
    assert completed.returncode == 0
    assert (output_dir / "overridden_report.json").exists()
    assert (output_dir / "report.json").exists()


def test_pipeline_discovers_inputs_from_run_dir(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    run_dir = tmp_path / "run_2026-03-15_001"
    (run_dir / "scanner").mkdir(parents=True)
    (run_dir / "nested" / "http").mkdir(parents=True)
    (run_dir / "evidence" / "screenshots").mkdir(parents=True)

    sample_map = {
        run_dir / "scanner" / "scan_nuclei.jsonl": root / "sample_nuclei.jsonl",
        run_dir / "scanner" / "scan_burp.xml": root / "sample_burp_issues.xml",
        run_dir / "scanner" / "scan_ffuf.json": root / "sample_ffuf.json",
        run_dir / "nested" / "http" / "scan_httpx.jsonl": root / "sample_httpx.jsonl",
        run_dir / "scan_nikto.json": root / "sample_nikto.json",
    }
    for destination_path, source_path in sample_map.items():
        destination_path.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")

    output_dir = tmp_path / "artifacts"
    command = [
        sys.executable,
        "pipeline.py",
        "--target",
        "https://www.example.org",
        "--author",
        "pytest",
        "--run-dir",
        str(run_dir),
        "--include-banner",
        "--docx",
        "--output-dir",
        str(output_dir),
    ]
    completed = subprocess.run(command, cwd=root, check=False)
    assert completed.returncode == 0
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.md").exists()
    assert (output_dir / "report.docx").exists()


def test_pipeline_run_dir_uses_default_output_dir_and_skips_invalid_candidates(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    project_root = root.parent
    run_dir = tmp_path / "run_2026-03-15_002"
    (run_dir / "scanner").mkdir(parents=True)
    (run_dir / "nested").mkdir(parents=True)

    (run_dir / "scanner" / "nuclei_empty.jsonl").write_text("", encoding="utf-8")
    (run_dir / "scanner" / "scan_nuclei.jsonl").write_text((root / "sample_nuclei.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    (run_dir / "scanner" / "broken_ffuf.json").write_text("{broken", encoding="utf-8")
    (run_dir / "scanner" / "scan_ffuf.json").write_text((root / "sample_ffuf.json").read_text(encoding="utf-8"), encoding="utf-8")
    (run_dir / "nested" / "scan_httpx.jsonl").write_text((root / "sample_httpx.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    (run_dir / "nested" / "broken_burp.xml").write_text("<issues>", encoding="utf-8")
    (run_dir / "scan_nikto.json").write_text((root / "sample_nikto.json").read_text(encoding="utf-8"), encoding="utf-8")

    default_output_dir = project_root / "artifacts" / run_dir.name
    if default_output_dir.exists():
        import shutil

        shutil.rmtree(default_output_dir)

    command = [
        sys.executable,
        "pipeline.py",
        "--target",
        "https://www.example.org",
        "--author",
        "pytest",
        "--run-dir",
        str(run_dir),
        "--include-banner",
    ]
    completed = subprocess.run(command, cwd=root, check=False, capture_output=True, text=True)
    assert completed.returncode == 0
    assert "[WARN]" in completed.stdout
    assert "nuclei" in completed.stdout
    assert "burp" in completed.stdout
    assert (default_output_dir / "report.json").exists()
    assert (default_output_dir / "report.md").exists()
    assert not (default_output_dir / "report.docx").exists()
