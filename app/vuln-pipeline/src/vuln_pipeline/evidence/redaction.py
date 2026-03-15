from __future__ import annotations

import re
from pathlib import Path

from vuln_pipeline.models import ArtifactRef
from vuln_pipeline.utils import ensure_directory

SENSITIVE_PATTERNS = [
    (re.compile(r"(?im)^(authorization:\s*)(.+)$"), r"\1<redacted>"),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._\-+=/]+\b"), "Bearer <redacted>"),
    (re.compile(r"(?im)^(cookie:\s*)(.+)$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(set-cookie:\s*)(.+)$"), r"\1<redacted>"),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b"), "<redacted-jwt>"),
    (re.compile(r"(?i)(session(?:id)?=)([^;\s&]+)"), r"\1<redacted>"),
    (re.compile(r"\b([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), r"\1***\2"),
    (re.compile(r"([?&](?:token|key|apikey|api_key|session|password)=)([^&\s]+)", re.IGNORECASE), r"\1<redacted>"),
]


def redact_text(text: str) -> str:
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def save_artifact_pair(base_dir: Path, stem: str, kind: str, content: str | None) -> ArtifactRef | None:
    if not content:
        return None
    raw_dir = ensure_directory(base_dir / "raw")
    redacted_dir = ensure_directory(base_dir / "redacted")
    suffix = ".txt"
    raw_path = raw_dir / f"{stem}_{kind}{suffix}"
    redacted_path = redacted_dir / f"{stem}_{kind}{suffix}"
    raw_path.write_text(content, encoding="utf-8")
    redacted_path.write_text(redact_text(content), encoding="utf-8")
    return ArtifactRef(kind=kind, raw_path=str(raw_path), redacted_path=str(redacted_path))
