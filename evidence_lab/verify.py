"""Integrity verification of a collected case against its manifest and handling log."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .core import CASE_SCHEMA, ZERO, canonical, case_file, digest, digest_many


def verify(
    case: Path | str, *, expected_manifest: str | None = None, expected_handling: str | None = None, jobs: int = 1
) -> dict[str, Any]:
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    case = Path(case)
    if (case / "INCOMPLETE.json").exists():
        raise ValueError("Collection is incomplete")
    for name in ("manifest.json", "handling.jsonl", "anchor.json"):
        if (case / name).is_symlink():
            raise ValueError("Case metadata must not be symlinks")
    manifest: dict[str, Any] = json.loads((case / "manifest.json").read_text())
    if manifest["schema"] != CASE_SCHEMA or not manifest["files"]:
        raise ValueError("Invalid manifest")
    anchor: dict[str, Any] = json.loads((case / "anchor.json").read_text())
    manifest_hash = digest(case / "manifest.json")
    if manifest_hash != anchor["manifest_sha256"] or (expected_manifest and manifest_hash != expected_manifest):
        raise ValueError("Manifest digest mismatch")
    previous = ZERO
    events: list[dict[str, Any]] = []
    for line in (case / "handling.jsonl").read_text().splitlines():
        event = json.loads(line)
        stored = event.pop("sha256")
        if event["sequence"] != len(events) + 1 or event["previous_sha256"] != previous:
            raise ValueError("Handling log order or chain mismatch")
        if hashlib.sha256(canonical(event)).hexdigest() != stored:
            raise ValueError("Handling event digest mismatch")
        previous = stored
        events.append(event)
    if previous != anchor["handling_sha256"] or (expected_handling and previous != expected_handling):
        raise ValueError("Handling log anchor mismatch")
    if not events or events[-1]["action"] != "collection_completed" or events[-1]["manifest_sha256"] != manifest_hash:
        raise ValueError("No matching completed collection event")
    listed = [entry["path"] for entry in manifest["files"]]
    if len(listed) != len(set(listed)):
        raise ValueError("Duplicate manifest paths")
    actual = set()
    for p in (case / "evidence").rglob("*"):
        if p.is_symlink():
            raise ValueError("Symlink found in evidence")
        if p.is_file():
            actual.add(p.relative_to(case / "evidence").as_posix())
    if actual != set(listed):
        raise ValueError("Evidence file inventory mismatch")
    paths = [case_file(case, entry["path"]) for entry in manifest["files"]]
    computed = digest_many(paths, jobs=jobs)
    copies = [event for event in events if event["action"] == "file_copied_and_verified"]
    for entry, path, got in zip(manifest["files"], paths, computed, strict=True):
        if not path.is_file() or path.stat().st_size != entry["bytes"] or got != entry["sha256"]:
            raise ValueError(f"Evidence digest or size mismatch: {entry['path']}")
        matches = [event for event in copies if event["path"] == entry["path"]]
        if len(matches) != 1 or matches[0]["sha256_of_copy"] != entry["sha256"]:
            raise ValueError("File and handling log disagree")
    return manifest
