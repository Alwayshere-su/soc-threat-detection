#!/usr/bin/env python3
"""校验 submission/ 的完整性与最终提交文件（只用标准库）。

等价于 submission/verify.py，但不需要 pandas，供 CI 使用。
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT / "submission"
EXPECTED_PREDICTION_SHA = "d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d"
EXPECTED_ROWS = 55837
EXPECTED_LABELS = {"benign", "suspicious", "malicious"}
ALLOWED_EXTRAS = {"README.md", "manifest.json"}

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"PASS  {message}")
    else:
        FAILURES.append(message)
        print(f"FAIL  {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_manifest() -> dict[str, str]:
    manifest = json.loads((SUBMISSION / "manifest.json").read_text(encoding="utf-8"))
    files: dict[str, str] = manifest["files"]
    check(manifest.get("version") == 1, "manifest version is 1")
    check(len(files) == 227, f"manifest lists {len(files)} files (expected 227)")

    mismatched = []
    missing = []
    for relative, expected in files.items():
        path = SUBMISSION / relative
        if not path.is_file():
            missing.append(relative)
        elif sha256(path) != expected:
            mismatched.append(relative)

    check(not missing, f"all manifest files exist ({len(missing)} missing)")
    check(not mismatched, f"all file hashes match ({len(mismatched)} mismatched)")
    for relative in (missing + mismatched)[:5]:
        print(f"      {relative}")

    listed = set(files)
    actual = {
        path.relative_to(SUBMISSION).as_posix()
        for path in SUBMISSION.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    extras = actual - listed - ALLOWED_EXTRAS
    check(not extras, f"no unlisted files ({len(extras)} extra)")
    for relative in sorted(extras)[:5]:
        print(f"      {relative}")

    return files


def check_submission(files: dict[str, str]) -> None:
    path = SUBMISSION / "res.csv"
    digest = sha256(path)
    check(digest == EXPECTED_PREDICTION_SHA, "res.csv SHA256 matches the recorded result")
    check(
        files.get("res.csv") == EXPECTED_PREDICTION_SHA,
        "manifest res.csv hash matches the recorded result",
    )

    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
        rows = list(reader)

    check(header == ["event_id", "pred_label"], "res.csv header is event_id,pred_label")
    check(len(rows) == EXPECTED_ROWS, f"res.csv has {len(rows)} rows (expected {EXPECTED_ROWS})")

    event_ids = [row[0] for row in rows if len(row) == 2]
    labels = {row[1] for row in rows if len(row) == 2}
    check(len(event_ids) == len(set(event_ids)), "event_id values are unique")
    check(labels <= EXPECTED_LABELS, f"labels are within {sorted(EXPECTED_LABELS)}")


def main() -> int:
    files = check_manifest()
    check_submission(files)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
