from __future__ import annotations

from pathlib import Path

_CURRENT = Path(__file__).resolve().parent
_SRC_PACKAGE = _CURRENT.parent / "src" / "vuln_pipeline"
__path__ = [str(_CURRENT), str(_SRC_PACKAGE)]
