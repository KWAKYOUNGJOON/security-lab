from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path, warnings: list[dict[str, Any]] | None = None) -> Iterable[dict[str, Any]]:
    seen_nonempty = False
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if line:
                seen_nonempty = True
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    if warnings is not None:
                        warnings.append(
                            {
                                "type": "malformed_jsonl",
                                "file": str(path),
                                "line": line_number,
                                "error": str(exc),
                            }
                        )
                    continue
                if isinstance(payload, dict):
                    yield payload
                elif warnings is not None:
                    warnings.append(
                        {
                            "type": "unexpected_jsonl_record",
                            "file": str(path),
                            "line": line_number,
                            "error": f"Expected object, got {type(payload).__name__}",
                        }
                    )
    if not seen_nonempty and warnings is not None:
        warnings.append({"type": "empty_file", "file": str(path), "error": "No non-empty JSONL lines found."})


def decode_maybe_base64(text: str | None, is_base64: bool) -> str:
    if not text:
        return ""
    if not is_base64:
        return text
    return base64.b64decode(text).decode("utf-8", errors="replace")
