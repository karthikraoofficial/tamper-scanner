"""Command-line interface for Tamper Scanner."""

from __future__ import annotations

import argparse
from pathlib import Path

from .scanner import build_manifest, compare_manifests, load_manifest, save_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and verify file integrity manifests.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser("baseline", help="Create a manifest for a directory.")
    baseline_parser.add_argument("root", type=Path)
    baseline_parser.add_argument("manifest", type=Path)

    scan_parser = subparsers.add_parser("scan", help="Compare a directory with a manifest.")
    scan_parser.add_argument("root", type=Path)
    scan_parser.add_argument("manifest", type=Path)

    arguments = parser.parse_args()
    if arguments.command == "baseline":
        save_manifest(build_manifest(arguments.root, exclude=arguments.manifest), arguments.manifest)
        print(f"Baseline written to {arguments.manifest}")
        return 0

    differences = compare_manifests(
        load_manifest(arguments.manifest),
        build_manifest(arguments.root, exclude=arguments.manifest),
    )
    if not any(differences.values()):
        print("No changes detected.")
        return 0

    for category, paths in differences.items():
        for path in paths:
            print(f"{category}: {path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
