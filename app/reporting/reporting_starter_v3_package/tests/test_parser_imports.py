from __future__ import annotations

import importlib

import common
import severity_engine


def test_parsers_are_importable_as_modules() -> None:
    modules = [
        "parsers.nuclei_parser",
        "parsers.burp_xml_parser",
        "parsers.ffuf_json_parser",
        "parsers.httpx_jsonl_parser",
        "parsers.nikto_json_parser",
        "parsers.merge_reports",
        "parsers.dedupe_findings",
    ]
    for module_name in modules:
        importlib.import_module(module_name)


def test_top_level_shims_match_parser_modules() -> None:
    importlib.import_module("parsers.common")
    importlib.import_module("parsers.severity_engine")

    assert hasattr(common, "load_json")
    assert hasattr(common, "write_report")
    assert hasattr(severity_engine, "normalize_severity")
    assert hasattr(severity_engine, "map_nuclei_severity")
