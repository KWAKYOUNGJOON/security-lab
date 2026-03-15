from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable

DEFAULT_REFERENCES = {
    "kisa_guide": "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드",
    "owasp": "OWASP Top 10",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}의 {line_number}번째 줄 JSON을 해석할 수 없습니다: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"{path}의 {line_number}번째 줄은 JSON 객체여야 합니다.")
            yield payload


def load_mapping(path: Path | None) -> Dict[str, Any]:
    if path is None:
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"매핑 파일은 JSON 객체여야 합니다: {path}")
    return data


def safe_str(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def truncate_text(value: Any, limit: int = 4000) -> str:
    text = safe_str(value, "") or ""
    return text[:limit]


def make_report_meta(target: str, author: str | None, assessment_scope: list[str]) -> Dict[str, Any]:
    return {
        "project_name": f"{target} 웹 취약점 진단 보고서",
        "target": target,
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "assessment_scope": assessment_scope,
        "customer": None,
        "author": author,
        "template": "kisa_web",
        "references": dict(DEFAULT_REFERENCES),
    }


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
