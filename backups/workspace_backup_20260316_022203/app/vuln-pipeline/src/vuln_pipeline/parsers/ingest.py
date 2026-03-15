from __future__ import annotations

from pathlib import Path

SUPPORTED = {
    "burp": {".xml"},
    "nuclei": {".json", ".jsonl"},
    "httpx": {".jsonl"},
}


def collect_inputs(
    explicit: dict[str, list[Path] | None],
    directories: dict[str, Path | None],
) -> tuple[dict[str, list[Path]], dict]:
    manifest: dict[str, object] = {"ingested": {}, "warnings": []}
    collected: dict[str, list[Path]] = {tool: [] for tool in SUPPORTED}
    warnings: list[str] = manifest["warnings"]  # type: ignore[assignment]

    for tool, paths in explicit.items():
        for path in paths or []:
            if _is_supported(tool, path):
                collected[tool].append(path)
            else:
                warnings.append(f"Unsupported {tool} file skipped: {path}")

    for tool, directory in directories.items():
        if not directory or not directory.exists():
            continue
        for path in sorted(item for item in directory.iterdir() if item.is_file()):
            if _is_supported(tool, path):
                collected[tool].append(path)
            else:
                warnings.append(f"Unsupported {tool} file skipped: {path}")

    for tool in collected:
        deduped = []
        seen: set[str] = set()
        for path in collected[tool]:
            key = str(path.resolve())
            if key not in seen:
                deduped.append(path)
                seen.add(key)
            else:
                warnings.append(f"Duplicate {tool} file skipped: {path}")
        collected[tool] = deduped
        manifest["ingested"][tool] = [str(path) for path in deduped]
    return collected, manifest


def _is_supported(tool: str, path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED[tool]
