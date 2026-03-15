from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


pytest.importorskip("docx")


def test_docx_generator_creates_docx(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    output = tmp_path / "report.docx"
    command = [
        sys.executable,
        "docx_generator.py",
        "--input",
        "sample_findings.json",
        "--schema",
        "vulnerability-report.schema.json",
        "--output",
        str(output),
    ]
    completed = subprocess.run(command, cwd=root, check=False)
    assert completed.returncode == 0
    assert output.exists()


def test_pipeline_generates_docx_with_option(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    output_dir = tmp_path / "pipeline_docx"
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
    assert (output_dir / "report.md").exists()
    assert (output_dir / "report.docx").exists()
