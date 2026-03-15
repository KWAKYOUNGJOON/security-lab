from parsers.dedupe_findings import merge_findings
from parsers.merge_reports import merge_reports


def test_merge_reports_combines_scope_and_findings(tmp_path) -> None:
    report_a = tmp_path / "a.json"
    report_b = tmp_path / "b.json"

    report_a.write_text(
        """
        {
          "report_meta": {
            "project_name": "A",
            "target": "https://a",
            "generated_at": "2026-03-15T00:00:00+09:00",
            "assessment_scope": ["웹 애플리케이션"],
            "customer": null,
            "author": "tester",
            "template": "kisa_web",
            "references": {"owasp": "OWASP Top 10"}
          },
          "findings": [{"id": "WEB-001", "title": "A", "category": "정보노출", "severity": "low", "confidence": "medium", "status": "needs_review", "asset": "a", "description": "d", "impact": "i", "reproduction_steps": ["1"], "recommendation": ["1"], "tools": ["x"]}]
        }
        """,
        encoding="utf-8",
    )
    report_b.write_text(
        """
        {
          "report_meta": {
            "project_name": "B",
            "target": "https://a",
            "generated_at": "2026-03-15T00:00:01+09:00",
            "assessment_scope": ["웹 서버 설정"],
            "customer": null,
            "author": "tester",
            "template": "kisa_web",
            "references": {"kisa_guide": "KISA"}
          },
          "findings": [{"id": "WEB-001", "title": "B", "category": "보안설정", "severity": "medium", "confidence": "medium", "status": "needs_review", "asset": "b", "description": "d", "impact": "i", "reproduction_steps": ["1"], "recommendation": ["1"], "tools": ["y"]}]
        }
        """,
        encoding="utf-8",
    )

    merged = merge_reports([report_a, report_b])
    assert merged["report_meta"]["assessment_scope"] == ["웹 애플리케이션", "웹 서버 설정"]
    assert len(merged["findings"]) == 2


def test_merge_findings_preserves_richer_metadata() -> None:
    findings = [
        {
            "id": "WEB-001",
            "title": "관리자 페이지 노출",
            "category": "정보노출",
            "severity": "medium",
            "confidence": "medium",
            "status": "needs_review",
            "asset": "https://example.org",
            "host": "example.org",
            "url": "https://example.org/admin",
            "method": "GET",
            "parameter": None,
            "port": 443,
            "description": "a",
            "impact": "a",
            "severity_reason": ["one"],
            "evidence": [{"type": "text", "content": "a", "path": None}],
            "reproduction_steps": ["one"],
            "recommendation": ["one"],
            "references": {"owasp": ["A01"]},
            "tools": ["httpx"],
            "raw_source": ["httpx.jsonl"],
            "manual_verified": False,
            "duplicate_group": None,
            "notes": None,
        },
        {
            "id": "WEB-002",
            "title": "관리자 페이지 노출",
            "category": "정보노출",
            "severity": "high",
            "confidence": "high",
            "status": "needs_review",
            "asset": "https://example.org",
            "host": "example.org",
            "url": "https://example.org/admin",
            "method": "GET",
            "parameter": None,
            "port": 443,
            "description": "b",
            "impact": "b",
            "severity_reason": ["two"],
            "evidence": [{"type": "text", "content": "b", "path": None}],
            "reproduction_steps": ["two"],
            "recommendation": ["two"],
            "references": {"kisa": ["III"]},
            "tools": ["burp"],
            "raw_source": ["issues.xml"],
            "manual_verified": True,
            "duplicate_group": "grp",
            "notes": "memo",
        },
    ]

    merged = merge_findings(findings)
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"
    assert merged[0]["manual_verified"] is True
    assert set(merged[0]["tools"]) == {"httpx", "burp"}
