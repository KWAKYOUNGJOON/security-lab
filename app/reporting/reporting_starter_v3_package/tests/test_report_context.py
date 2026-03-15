from pathlib import Path

from docx_generator import build_docx_context
from parsers.common import load_json
from report_generator import build_render_context, normalize


def test_report_context_reused_for_docx() -> None:
    data = normalize(load_json(Path("sample_findings.json")))
    markdown_context = build_render_context(data)
    docx_context = build_docx_context(data)

    assert markdown_context == docx_context
