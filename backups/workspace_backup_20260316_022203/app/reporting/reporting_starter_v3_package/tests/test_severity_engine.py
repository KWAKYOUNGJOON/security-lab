from parsers.severity_engine import (
    classify_ffuf_result,
    classify_httpx_path,
    classify_nikto_message,
    map_burp_severity,
    map_nuclei_severity,
)


def test_map_nuclei_severity() -> None:
    assert map_nuclei_severity("high") == "high"
    assert map_nuclei_severity("UNKNOWN") == "info"


def test_map_burp_severity() -> None:
    assert map_burp_severity("Medium") == "medium"
    assert map_burp_severity("Information") == "info"


def test_classify_ffuf_result() -> None:
    title, category, severity = classify_ffuf_result("https://example.org/.env", 200)
    assert title == "민감 파일 또는 백업 파일 노출 가능성"
    assert category == "정보노출"
    assert severity == "high"


def test_classify_httpx_path() -> None:
    assert classify_httpx_path("https://example.org/admin", 200) == ("관리자 또는 인증 경로 노출", "노출경로", "medium")
    assert classify_httpx_path("https://example.org/assets/app.js", 200) is None


def test_classify_nikto_message() -> None:
    assert classify_nikto_message("phpinfo() file found.", "/phpinfo.php")[2] == "high"
