from override_engine import apply_overrides


def test_apply_overrides_updates_matched_finding() -> None:
    report = {
        "report_meta": {"project_name": "A"},
        "findings": [
            {
                "id": "WEB-001",
                "title": "관리자 페이지 노출",
                "url": "https://example.org/admin",
                "severity": "medium",
                "confidence": "medium",
                "status": "needs_review",
                "manual_verified": False,
                "notes": None,
            }
        ],
    }
    override = {
        "report_meta": {"customer": "고객사"},
        "findings": [
            {
                "match": {"title": "관리자 페이지 노출", "url": "https://example.org/admin"},
                "override": {"severity": "high", "manual_verified": True, "notes": "수동 검증 완료"},
            }
        ],
    }

    updated = apply_overrides(report, override)
    assert updated["report_meta"]["customer"] == "고객사"
    assert updated["findings"][0]["severity"] == "high"
    assert updated["findings"][0]["manual_verified"] is True
    assert updated["findings"][0]["notes"] == "수동 검증 완료"
