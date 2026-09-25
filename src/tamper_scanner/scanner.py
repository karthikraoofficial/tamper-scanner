"""Create and compare SHA-256 file manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path, exclude: Path | None = None) -> dict[str, str]:
    root = root.resolve()
    excluded_path = exclude.resolve() if exclude else None
    return {
        str(path.relative_to(root)): file_hash(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.resolve() != excluded_path
    }


def save_manifest(manifest: dict[str, str], path: Path) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_manifest(path: Path) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))


def compare_manifests(expected: dict[str, str], actual: dict[str, str]) -> dict[str, list[str]]:
    expected_paths = set(expected)
    actual_paths = set(actual)
    return {
        "added": sorted(actual_paths - expected_paths),
        "changed": sorted(path for path in expected_paths & actual_paths if expected[path] != actual[path]),
        "removed": sorted(expected_paths - actual_paths),
    }
