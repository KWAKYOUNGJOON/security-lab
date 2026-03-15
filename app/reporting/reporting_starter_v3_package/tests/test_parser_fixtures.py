from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixture_runner import FixtureCase, collect_real_fixture_cases, collect_sample_fixture_cases, run_parser


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_fixture_report(report: dict, case: FixtureCase) -> None:
    findings = report["findings"]
    assert len(findings) >= case.expected.get("min_findings", 1)

    titles = [finding["title"] for finding in findings]
    for expected_title in case.expected.get("contains_titles", []):
        assert expected_title in titles

    if case.expected.get("contains_tools"):
        tools = {tool for finding in findings for tool in finding.get("tools", [])}
        for expected_tool in case.expected["contains_tools"]:
            assert expected_tool in tools

    if case.expected.get("allowed_severities"):
        allowed = set(case.expected["allowed_severities"])
        for finding in findings:
            assert finding["severity"] in allowed


@pytest.mark.parametrize("case", collect_sample_fixture_cases(), ids=lambda case: case.id)
def test_sample_fixtures(case: FixtureCase, tmp_path: Path) -> None:
    output_path = tmp_path / f"{case.tool}.json"
    run_parser(
        case.tool,
        case.input_path,
        output_path,
        case.meta["target"],
        case.meta["author"],
        case.meta.get("extra_args"),
        case.meta.get("mapping", False),
    )
    assert_fixture_report(load_json(output_path), case)


@pytest.mark.parametrize("case", collect_real_fixture_cases(), ids=lambda case: case.id)
def test_real_fixtures(case: FixtureCase, tmp_path: Path) -> None:
    output_path = tmp_path / f"{case.tool}_real.json"
    run_parser(
        case.tool,
        case.input_path,
        output_path,
        case.meta["target"],
        case.meta["author"],
        case.meta.get("extra_args"),
        case.meta.get("mapping", False),
    )
    assert_fixture_report(load_json(output_path), case)
