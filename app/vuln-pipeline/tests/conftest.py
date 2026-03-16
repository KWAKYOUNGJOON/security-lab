from __future__ import annotations

import sys
from pathlib import Path


# Keep pytest import resolution aligned with the local src layout.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    value = str(candidate)
    if value not in sys.path:
        sys.path.insert(0, value)
