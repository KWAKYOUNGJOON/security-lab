#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from shutil import copyfile
from typing import Any

from override_engine import apply_override_file


PARSER_SPECS: dict[str, dict[str, Any]] = {
    "nuclei": {
        "script": "parsers/nuclei_parser.py",
        "output": "nuclei_report.json",
        "named_patterns": ("*nuclei*.jsonl",),
    },
    "burp": {
        "script": "parsers/burp_xml_parser.py",
        "output": "burp_report.json",
        "named_patterns": ("*burp*.xml",),
    },
    "ffuf": {
        "script": "parsers/ffuf_json_parser.py",
        "output": "ffuf_report.json",
        "named_patterns": ("*ffuf*.json",),
    },
    "httpx": {
        "script": "parsers/httpx_jsonl_parser.py",
        "output": "httpx_report.json",
        "named_patterns": ("*httpx*.jsonl",),
    },
    "nikto": {
        "script": "parsers/nikto_json_parser.py",
        "output": "nikto_report.json",
        "named_patterns": ("*nikto*.json",),
    },
}


def log_info(message: str) -> None:
    print(f"[INFO] {message}")


def log_warning(message: str) -> None:
    print(f"[WARN] {message}")


def run_step(command: list[str], cwd: Path) -> None:
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def resolve_path(base: Path, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path


def sniff_json_tool(path: Path) -> tuple[str | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        return None, f"파일을 읽을 수 없습니다: {path} ({exc})"
    except UnicodeDecodeError:
        return None, f"UTF-8 JSON으로 읽을 수 없습니다: {path}"
    except json.JSONDecodeError as exc:
        return None, f"잘못된 JSON 형식이라 건너뜁니다: {path} ({exc})"

    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return "ffuf", None
        if isinstance(payload.get("hosts"), list):
            return "nikto", None
        if isinstance(payload.get("vulnerabilities"), list):
            return "nikto", None
    if isinstance(payload, list) and payload:
        first_item = payload[0]
        if isinstance(first_item, dict) and isinstance(first_item.get("vulnerabilities"), list):
            return "nikto", None
    return None, f"지원하는 JSON 스캐너 형식이 아닙니다: {path}"


def sniff_jsonl_tool(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            saw_payload = False
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                saw_payload = True
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    return None, f"잘못된 JSONL 형식이라 건너뜁니다: {path} ({exc})"
                if "template-id" in payload or isinstance(payload.get("info"), dict):
                    return "nuclei", None
                if any(key in payload for key in ("webserver", "tech", "tls-grab", "favicon")):
                    return "httpx", None
                if any(key in payload for key in ("input", "port", "scheme")) and "url" in payload:
                    return "httpx", None
            if not saw_payload:
                return None, f"빈 JSONL 파일이라 건너뜁니다: {path}"
    except OSError as exc:
        return None, f"파일을 읽을 수 없습니다: {path} ({exc})"
    except UnicodeDecodeError:
        return None, f"UTF-8 JSONL로 읽을 수 없습니다: {path}"
    return None, f"지원하는 JSONL 스캐너 형식이 아닙니다: {path}"


def sniff_xml_tool(path: Path) -> tuple[str | None, str | None]:
    try:
        root = ET.parse(path).getroot()
    except OSError as exc:
        return None, f"파일을 읽을 수 없습니다: {path} ({exc})"
    except ET.ParseError as exc:
        return None, f"잘못된 XML 형식이라 건너뜁니다: {path} ({exc})"
    if root.tag.lower() == "issues":
        return "burp", None
    return None, f"지원하는 XML 스캐너 형식이 아닙니다: {path}"


def identify_tool(path: Path) -> tuple[str | None, str | None]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return sniff_json_tool(path)
    if suffix == ".jsonl":
        return sniff_jsonl_tool(path)
    if suffix == ".xml":
        return sniff_xml_tool(path)
    return None, None


def candidate_sort_key(path: Path, tool: str, run_dir: Path) -> tuple[int, int, int, str]:
    name = path.name.lower()
    try:
        depth = len(path.relative_to(run_dir).parts)
    except ValueError:
        depth = len(path.parts)
    priority = 0 if tool in name else 1
    size = 0
    try:
        size = path.stat().st_size
    except OSError:
        pass
    return priority, depth, -size, str(path).lower()


def inspect_candidate(path: Path, expected_tool: str | None = None) -> tuple[bool, str | None]:
    try:
        if path.stat().st_size == 0:
            return False, f"빈 파일이라 건너뜁니다: {path}"
    except OSError as exc:
        return False, f"파일 상태를 확인할 수 없습니다: {path} ({exc})"

    actual_tool, warning = identify_tool(path)
    if actual_tool is None:
        return False, warning
    if expected_tool and actual_tool != expected_tool:
        return False, f"예상한 스캐너({expected_tool})와 실제 형식({actual_tool})이 달라 건너뜁니다: {path}"
    return True, None


def discover_run_inputs(run_dir: Path) -> tuple[dict[str, Path], list[str]]:
    discovered: dict[str, Path] = {}
    warnings: list[str] = []
    seen_warnings: set[str] = set()
    files = sorted(path for path in run_dir.rglob("*") if path.is_file())

    for tool, spec in PARSER_SPECS.items():
        for pattern in spec["named_patterns"]:
            matches = sorted(
                (path for path in run_dir.rglob(pattern) if path.is_file()),
                key=lambda path: candidate_sort_key(path, tool, run_dir),
            )
            for candidate in matches:
                valid, warning = inspect_candidate(candidate, expected_tool=tool)
                if valid:
                    discovered[tool] = candidate
                    break
                if warning and warning not in seen_warnings:
                    seen_warnings.add(warning)
                    warnings.append(warning)
            if tool in discovered:
                break

    for path in files:
        tool, warning = identify_tool(path)
        if tool is None:
            if warning and warning not in seen_warnings:
                seen_warnings.add(warning)
                warnings.append(warning)
            continue
        if tool not in discovered:
            valid, inspect_warning = inspect_candidate(path, expected_tool=tool)
            if valid:
                discovered[tool] = path
            elif inspect_warning and inspect_warning not in seen_warnings:
                seen_warnings.add(inspect_warning)
                warnings.append(inspect_warning)

    return discovered, warnings


def parser_extra_args(tool: str, args: argparse.Namespace) -> list[str]:
    if tool in {"nuclei", "burp"}:
        return ["--mapping", args.mapping]
    if tool == "httpx" and args.include_banner:
        return ["--include-banner"]
    return []


def append_input(
    commands: list[list[str]],
    parser_script: str,
    input_path: Path | None,
    output_path: Path,
    target: str,
    author: str | None,
    extra_args: list[str] | None = None,
) -> None:
    if not input_path:
        return
    command = [
        sys.executable,
        parser_script,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--target",
        target,
    ]
    if author:
        command.extend(["--author", author])
    if extra_args:
        command.extend(extra_args)
    commands.append(command)


def default_output_dir(base: Path, run_dir: Path | None) -> Path:
    if run_dir:
        return base.parent / "artifacts" / run_dir.name
    return base / "artifacts" / "pipeline_run"


def main() -> None:
    parser = argparse.ArgumentParser(description="취약점 결과를 병합하고 Markdown/DOCX 보고서를 생성합니다.")
    parser.add_argument("--target", required=True, help="대상 URL 또는 식별자")
    parser.add_argument("--author", default=None, help="작성자")
    parser.add_argument("--output-dir", default=None, help="산출물 디렉터리")
    parser.add_argument("--run-dir", default=None, help="run 폴더를 직접 읽어 입력 파일을 자동 탐지합니다.")
    parser.add_argument("--schema", default="vulnerability-report.schema.json", help="JSON Schema 경로")
    parser.add_argument("--template-dir", default="templates", help="Markdown 템플릿 디렉터리")
    parser.add_argument("--template", default="report.md.j2", help="Markdown 템플릿 파일명")
    parser.add_argument("--mapping", default="mappings/kisa_owasp_mapping.json", help="매핑 파일 경로")
    parser.add_argument("--override-file", default=None, help="severity/manual override JSON 파일 경로")
    parser.add_argument("--nuclei", default=None, help="nuclei JSONL 파일 경로")
    parser.add_argument("--burp", default=None, help="Burp XML 파일 경로")
    parser.add_argument("--ffuf", default=None, help="ffuf JSON 파일 경로")
    parser.add_argument("--httpx", default=None, help="httpx JSONL 파일 경로")
    parser.add_argument("--nikto", default=None, help="Nikto JSON 파일 경로")
    parser.add_argument("--include-banner", action="store_true", help="httpx 서버 배너 항목 포함")
    parser.add_argument("--skip-validation", action="store_true", help="보고서 생성 시 스키마 검증 생략")
    parser.add_argument("--docx", action="store_true", help="Markdown과 함께 DOCX 보고서도 생성")
    args = parser.parse_args()

    base = Path(__file__).resolve().parent
    run_dir = resolve_path(base, args.run_dir)
    if run_dir and (not run_dir.exists() or not run_dir.is_dir()):
        raise SystemExit(f"run 폴더를 찾을 수 없습니다: {run_dir}")

    output_dir = resolve_path(base, args.output_dir) if args.output_dir else default_output_dir(base, run_dir)
    if output_dir is None:
        raise SystemExit("산출물 경로를 계산할 수 없습니다.")
    output_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"산출물 경로: {output_dir}")

    resolved_inputs: dict[str, Path | None] = {
        "nuclei": resolve_path(base, args.nuclei),
        "burp": resolve_path(base, args.burp),
        "ffuf": resolve_path(base, args.ffuf),
        "httpx": resolve_path(base, args.httpx),
        "nikto": resolve_path(base, args.nikto),
    }

    if run_dir:
        log_info(f"run 폴더 자동 탐지 시작: {run_dir}")
        discovered_inputs, discovery_warnings = discover_run_inputs(run_dir)
        for warning in discovery_warnings:
            log_warning(warning)
        for tool, path in discovered_inputs.items():
            if resolved_inputs[tool] is None:
                resolved_inputs[tool] = path
        log_info("자동 탐지 결과:")
        for tool in PARSER_SPECS:
            detected = resolved_inputs[tool]
            if detected:
                log_info(f"  - {tool}: {detected}")
            else:
                log_warning(f"{tool} 입력이 없어 건너뜁니다.")

    parser_outputs: list[Path] = []
    commands: list[list[str]] = []
    for tool, input_path in resolved_inputs.items():
        output_path = output_dir / PARSER_SPECS[tool]["output"]
        append_input(
            commands,
            PARSER_SPECS[tool]["script"],
            input_path,
            output_path,
            args.target,
            args.author,
            parser_extra_args(tool, args),
        )
        if input_path:
            parser_outputs.append(output_path)

    if not parser_outputs:
        raise SystemExit("최소 하나 이상의 입력 파일이 필요합니다.")

    for command in commands:
        run_step(command, base)

    merged_output = output_dir / "merged_report.json"
    run_step(
        [sys.executable, "parsers/merge_reports.py", "--inputs", *[str(path) for path in parser_outputs], "--output", str(merged_output)],
        base,
    )

    deduped_output = output_dir / "deduped_report.json"
    run_step([sys.executable, "parsers/dedupe_findings.py", "--input", str(merged_output), "--output", str(deduped_output)], base)

    report_input = deduped_output
    if args.override_file:
        overridden_output = output_dir / "overridden_report.json"
        override_path = resolve_path(base, args.override_file)
        if override_path is None:
            raise SystemExit("override 파일 경로를 확인할 수 없습니다.")
        apply_override_file(deduped_output, overridden_output, override_path)
        report_input = overridden_output

    report_json_output = output_dir / "report.json"
    copyfile(report_input, report_json_output)

    markdown_output = output_dir / "report.md"
    report_command = [
        sys.executable,
        "report_generator.py",
        "--input",
        str(report_input),
        "--schema",
        args.schema,
        "--template-dir",
        args.template_dir,
        "--template",
        args.template,
        "--output",
        str(markdown_output),
    ]
    if args.skip_validation:
        report_command.append("--skip-validation")
    run_step(report_command, base)

    if args.docx:
        docx_output = output_dir / "report.docx"
        docx_command = [
            sys.executable,
            "docx_generator.py",
            "--input",
            str(report_input),
            "--schema",
            args.schema,
            "--output",
            str(docx_output),
        ]
        if args.skip_validation:
            docx_command.append("--skip-validation")
        run_step(docx_command, base)

    print(f"[+] 파이프라인 완료: {output_dir}")


if __name__ == "__main__":
    main()
