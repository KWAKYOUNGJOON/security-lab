from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
MAPPING = ROOT / "mappings" / "kisa_owasp_mapping.json"

PARSER_CONFIG = {
    "nuclei": {"script": "parsers/nuclei_parser.py", "ext": "jsonl"},
    "burp": {"script": "parsers/burp_xml_parser.py", "ext": "xml"},
    "ffuf": {"script": "parsers/ffuf_json_parser.py", "ext": "json"},
    "httpx": {"script": "parsers/httpx_jsonl_parser.py", "ext": "jsonl"},
    "nikto": {"script": "parsers/nikto_json_parser.py", "ext": "json"},
}


@dataclass
class FixtureCase:
    suite: str
    tool: str
    name: str
    input_path: Path
    meta: dict[str, Any]
    expected: dict[str, Any]

    @property
    def id(self) -> str:
        return f"{self.suite}:{self.tool}:{self.name}"


def run_parser(
    tool: str,
    input_path: Path,
    output_path: Path,
    target: str,
    author: str,
    extra_args: list[str] | None = None,
    use_mapping: bool = False,
) -> None:
    config = PARSER_CONFIG[tool]
    command = [
        sys.executable,
        config["script"],
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--target",
        target,
        "--author",
        author,
    ]
    if use_mapping:
        command.extend(["--mapping", str(MAPPING)])
    if extra_args:
        command.extend(extra_args)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    assert completed.returncode == 0


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_case(suite: str, tool: str, case_name: str, input_path: Path, meta: dict[str, Any], expected: dict[str, Any]) -> FixtureCase:
    if not input_path.exists():
        raise FileNotFoundError(f"fixture input 파일이 없습니다: {input_path}")
    if "target" not in meta:
        raise ValueError(f"fixture meta에 target이 필요합니다: {case_name}")
    meta.setdefault("author", f"{suite}-fixture-test")
    meta.setdefault("mapping", False)
    meta.setdefault("extra_args", [])
    expected.setdefault("min_findings", 1)
    expected.setdefault("contains_titles", [])
    expected.setdefault("contains_tools", [])
    expected.setdefault("allowed_severities", [])
    return FixtureCase(suite, tool, case_name, input_path, meta, expected)


def collect_real_fixture_cases() -> list[FixtureCase]:
    base = ROOT / "real_fixtures"
    cases: list[FixtureCase] = []
    for tool, config in PARSER_CONFIG.items():
        tool_dir = base / tool
        for meta_path in sorted(tool_dir.glob("*.meta.json")):
            case_name = meta_path.name[: -len(".meta.json")]
            input_path = tool_dir / f"{case_name}.input.{config['ext']}"
            expected_path = tool_dir / f"{case_name}.expected.json"
            meta = load_json(meta_path)
            expected = load_json(expected_path) if expected_path.exists() else {}
            cases.append(build_case("real", tool, case_name, input_path, meta, expected))
    return cases


def collect_sample_fixture_cases() -> list[FixtureCase]:
    return [
        build_case("sample", "nuclei", "sample_nuclei", ROOT / "sample_nuclei.jsonl", {"target": "https://www.example.org", "author": "sample-test", "mapping": True}, {"min_findings": 1}),
        build_case("sample", "burp", "sample_burp", ROOT / "sample_burp_issues.xml", {"target": "https://www.example.org", "author": "sample-test", "mapping": True}, {"min_findings": 1}),
        build_case("sample", "ffuf", "sample_ffuf", ROOT / "sample_ffuf.json", {"target": "https://www.example.org", "author": "sample-test"}, {"min_findings": 1}),
        build_case("sample", "httpx", "sample_httpx", ROOT / "sample_httpx.jsonl", {"target": "https://www.example.org", "author": "sample-test", "extra_args": ["--include-banner"]}, {"min_findings": 1}),
        build_case("sample", "nikto", "sample_nikto", ROOT / "sample_nikto.json", {"target": "https://www.example.org", "author": "sample-test"}, {"min_findings": 1}),
    ]
