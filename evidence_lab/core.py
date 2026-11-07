"""Shared primitives: hashing, canonical JSON, safe case paths, constants."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "0.3.0"
ZERO = "0" * 64
CASE_SCHEMA = "digital-evidence-lab.case.v1"

#: Progress callbacks receive (done, total, human message).
ProgressCallback = Callable[[int, int, str], None]


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path: Path | str) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_many(paths: Iterable[Path | str], jobs: int = 1) -> list[str]:
    """Streamed SHA-256 for many files; output order always matches input order."""
    ordered = [Path(p) for p in paths]
    if jobs <= 1 or len(ordered) < 2:
        return [digest(path) for path in ordered]
    with ThreadPoolExecutor(max_workers=min(jobs, len(ordered))) as pool:
        return list(pool.map(digest, ordered))


def write_json(path: Path | str, value: Any) -> None:
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def checked_relative(value: str) -> PurePosixPath:
    p = PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts or "\\" in value or str(p) != value:
        raise ValueError(f"Unsafe relative path: {value!r}")
    return p


def case_file(case: Path | str, relative: str) -> Path:
    relative_path = checked_relative(relative)
    current = Path(case) / "evidence"
    if current.is_symlink():
        raise ValueError("Evidence root is a symlink")
    for part in relative_path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Evidence path contains a symlink")
    return current
