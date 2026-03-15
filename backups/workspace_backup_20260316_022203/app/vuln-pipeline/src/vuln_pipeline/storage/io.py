from __future__ import annotations

import json
import csv
from pathlib import Path
from typing import Any

from vuln_pipeline.models.schemas import to_plain_data
from vuln_pipeline.utils import ensure_directory


def write_json(path: Path, payload: Any) -> None:
    ensure_directory(path.parent)
    path.write_text(json.dumps(to_plain_data(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, payload: list[Any]) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        for row in payload:
            handle.write(json.dumps(to_plain_data(row), ensure_ascii=False))
            handle.write("\n")


def write_markdown(path: Path, content: str) -> None:
    ensure_directory(path.parent)
    path.write_text(content, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: to_plain_data(row.get(key, "")) for key in fieldnames})
