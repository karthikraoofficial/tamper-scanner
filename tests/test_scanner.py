from pathlib import Path

from tamper_scanner.scanner import build_manifest, compare_manifests


def test_manifest_detects_added_changed_and_removed_files(tmp_path: Path) -> None:
    (tmp_path / "changed.txt").write_text("before", encoding="utf-8")
    (tmp_path / "removed.txt").write_text("gone", encoding="utf-8")
    expected = build_manifest(tmp_path)

    (tmp_path / "changed.txt").write_text("after", encoding="utf-8")
    (tmp_path / "removed.txt").unlink()
    (tmp_path / "added.txt").write_text("new", encoding="utf-8")

    differences = compare_manifests(expected, build_manifest(tmp_path))

    assert differences == {
        "added": ["added.txt"],
        "changed": ["changed.txt"],
        "removed": ["removed.txt"],
    }
