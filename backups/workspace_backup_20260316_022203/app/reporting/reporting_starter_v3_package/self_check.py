#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_step(command: list[str], cwd: Path) -> None:
    print(f"[self-check] 실행: {' '.join(command)}")
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    base = Path(__file__).resolve().parent
    out_dir = base / "artifacts" / "self_check"
    out_dir.mkdir(parents=True, exist_ok=True)

    commands = [
        [
            sys.executable,
            "parsers/nuclei_parser.py",
            "--input",
            "sample_nuclei.jsonl",
            "--output",
            str(out_dir / "nuclei_report.json"),
            "--target",
            "https://www.example.org",
            "--author",
            "self-check",
            "--mapping",
            "mappings/kisa_owasp_mapping.json",
        ],
        [
            sys.executable,
            "parsers/burp_xml_parser.py",
            "--input",
            "sample_burp_issues.xml",
            "--output",
            str(out_dir / "burp_report.json"),
            "--target",
            "https://www.example.org",
            "--author",
            "self-check",
            "--mapping",
            "mappings/kisa_owasp_mapping.json",
        ],
        [
            sys.executable,
            "parsers/ffuf_json_parser.py",
            "--input",
            "sample_ffuf.json",
            "--output",
            str(out_dir / "ffuf_report.json"),
            "--target",
            "https://www.example.org",
            "--author",
            "self-check",
        ],
        [
            sys.executable,
            "parsers/httpx_jsonl_parser.py",
            "--input",
            "sample_httpx.jsonl",
            "--output",
            str(out_dir / "httpx_report.json"),
            "--target",
            "https://www.example.org",
            "--author",
            "self-check",
            "--include-banner",
        ],
        [
            sys.executable,
            "parsers/nikto_json_parser.py",
            "--input",
            "sample_nikto.json",
            "--output",
            str(out_dir / "nikto_report.json"),
            "--target",
            "https://www.example.org",
            "--author",
            "self-check",
        ],
        [
            sys.executable,
            "parsers/merge_reports.py",
            "--inputs",
            str(out_dir / "nuclei_report.json"),
            str(out_dir / "burp_report.json"),
            str(out_dir / "ffuf_report.json"),
            str(out_dir / "httpx_report.json"),
            str(out_dir / "nikto_report.json"),
            "--output",
            str(out_dir / "merged_report.json"),
        ],
        [
            sys.executable,
            "parsers/dedupe_findings.py",
            "--input",
            str(out_dir / "merged_report.json"),
            "--output",
            str(out_dir / "deduped_report.json"),
        ],
        [
            sys.executable,
            "report_generator.py",
            "--input",
            str(out_dir / "deduped_report.json"),
            "--schema",
            "vulnerability-report.schema.json",
            "--template-dir",
            "templates",
            "--template",
            "report.md.j2",
            "--output",
            str(out_dir / "report.md"),
        ],
    ]

    for command in commands:
        run_step(command, base)

    print(f"[self-check] 완료: {out_dir}")


if __name__ == "__main__":
    main()
