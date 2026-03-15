from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from vuln_pipeline.utils import ensure_directory


def package_run_output(run_root: Path, run_id: str, extra_manifest: dict[str, object] | None = None) -> dict[str, object]:
    delivery_dir = ensure_directory(run_root / "delivery")
    zip_path = delivery_dir / f"report_bundle_{run_id}.zip"
    include_dirs = [
        run_root / "reports",
        run_root / "deliverables",
        run_root / "report_data",
        run_root / "comparison",
        run_root / "artifacts",
    ]
    included_files: list[str] = []
    checksums: dict[str, str] = {}
    for folder in include_dirs:
        if not folder.exists():
            continue
        for path in folder.rglob("*"):
            if path.is_dir():
                continue
            rel = path.relative_to(run_root)
            if "artifacts" in rel.parts and "raw" in rel.parts:
                continue
            included_files.append(str(rel).replace("\\", "/"))
            checksums[str(rel).replace("\\", "/")] = _sha256(path)
    manifest = {
        "run_id": run_id,
        "zip_path": str(zip_path),
        "included_files": included_files,
        "raw_artifacts_excluded": True,
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    manifest_path = delivery_dir / "delivery_manifest.json"
    checksums_path = delivery_dir / "checksums.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    checksums_path.write_text(json.dumps(checksums, ensure_ascii=False, indent=2), encoding="utf-8")
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for rel in included_files:
            archive.write(run_root / rel, rel)
        archive.write(manifest_path, manifest_path.relative_to(run_root))
        archive.write(checksums_path, checksums_path.relative_to(run_root))
    return {
        "zip_path": str(zip_path),
        "delivery_manifest": str(manifest_path),
        "checksums": str(checksums_path),
        "included_files": included_files,
    }


def package_curated_output(
    run_root: Path,
    zip_name: str,
    include_files: list[Path],
    manifest_name: str,
    checksums_name: str,
    extra_manifest: dict[str, object] | None = None,
) -> dict[str, object]:
    delivery_dir = ensure_directory(run_root / "delivery")
    zip_path = delivery_dir / zip_name
    manifest_path = delivery_dir / manifest_name
    checksums_path = delivery_dir / checksums_name
    included_files: list[str] = []
    checksums: dict[str, str] = {}
    for path in include_files:
        if not path.exists() or path.is_dir():
            continue
        if path in {manifest_path, checksums_path}:
            continue
        rel = path.relative_to(run_root)
        rel_str = str(rel).replace("\\", "/")
        if rel_str not in included_files:
            included_files.append(rel_str)
            checksums[rel_str] = _sha256(path)
    manifest = {
        "zip_path": str(zip_path),
        "included_files": included_files,
        "excluded_files": [],
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    checksums_path.write_text(json.dumps(checksums, ensure_ascii=False, indent=2), encoding="utf-8")
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for rel in included_files:
            archive.write(run_root / rel, rel)
        archive.write(manifest_path, manifest_path.relative_to(run_root))
        archive.write(checksums_path, checksums_path.relative_to(run_root))
    return {
        "zip_path": str(zip_path),
        "delivery_manifest": str(manifest_path),
        "checksums": str(checksums_path),
        "included_files": included_files,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
