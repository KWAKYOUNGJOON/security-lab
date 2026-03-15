from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARSERS = ROOT / "parsers"
TESTS = ROOT / "tests"

for entry in [str(ROOT), str(PARSERS), str(TESTS)]:
    if entry not in sys.path:
        sys.path.insert(0, entry)
