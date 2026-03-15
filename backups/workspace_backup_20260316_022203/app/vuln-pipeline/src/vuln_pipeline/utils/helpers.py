from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(*parts: str | None, length: int = 12) -> str:
    digest = hashlib.sha256("||".join(part or "" for part in parts).encode("utf-8")).hexdigest()
    return digest[:length]


def safe_slug(value: str, fallback: str = "item") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or fallback

