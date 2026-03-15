from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run(command: list[str], cwd: Path) -> None:
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], root)
    run([sys.executable, "self_check.py"], root)
    run([sys.executable, "-m", "pytest", "-q"], root)


if __name__ == "__main__":
    main()
