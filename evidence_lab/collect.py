"""Logical collection: copy source files into a fresh case with integrity records."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .core import CASE_SCHEMA, VERSION, ZERO, ProgressCallback, canonical, case_file, digest, utc_now, write_json


def _signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def collect(
    source: Path | str, case: Path | str, *, operator: str, case_id: str, jobs: int = 1, progress: ProgressCallback | None = None
) -> dict[str, str]:
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    source, case = Path(source).absolute(), Path(case).absolute()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Source must be a non-symlink directory")
    source, case = source.resolve(), case.resolve()
    if source == case or source in case.parents or case in source.parents:
        raise ValueError("Source and case directories must not overlap")
    if not operator.strip() or not case_id.strip():
        raise ValueError("Operator and case ID are required")
    paths = sorted(source.rglob("*"))
    for path in paths:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"Unsupported source entry: {path.relative_to(source)}")
    files = [path for path in paths if path.is_file()]
    if not files:
        raise ValueError("Source has no files")
    case.mkdir(parents=False, exist_ok=False)
    (case / "evidence").mkdir()
    events: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    previous = ZERO

    def record(action: str, **detail: Any) -> None:
        nonlocal previous
        event = dict(sequence=len(events) + 1, observed_at=utc_now(), operator=operator, action=action, previous_sha256=previous, **detail)
        event["sha256"] = hashlib.sha256(canonical(event)).hexdigest()
        previous = str(event["sha256"])
        events.append(event)

    def copy_one(path: Path) -> dict[str, Any]:
        relative = path.relative_to(source).as_posix()
        target = case_file(case, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as incoming:
            before = os.fstat(incoming.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Only regular files may be copied")
            h = hashlib.sha256()
            with target.open("xb") as outgoing:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                    h.update(chunk)
                    outgoing.write(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            after = os.fstat(incoming.fileno())
        if _signature(before) != _signature(after):
            raise ValueError(f"Source changed during collection: {relative}")
        if digest(target) != h.hexdigest():
            raise ValueError(f"Copy digest mismatch: {relative}")
        return dict(path=relative, bytes=before.st_size, sha256=h.hexdigest(), source_mtime_ns=before.st_mtime_ns, collected_at=utc_now())

    def accept(entry: dict[str, Any]) -> None:
        entries.append(entry)
        record("file_copied_and_verified", path=entry["path"], bytes=entry["bytes"], sha256_of_copy=entry["sha256"])
        if progress:
            progress(len(entries), len(files), f"collected {entry['path']}")

    record("collection_started", case_id=case_id, tool_version=VERSION)
    try:
        if jobs > 1:
            # Copies run in parallel; handling events stay in deterministic sorted order.
            pool = ThreadPoolExecutor(max_workers=min(jobs, len(files)))
            try:
                futures = [pool.submit(copy_one, path) for path in files]
                for future in futures:
                    accept(future.result())
                pool.shutdown(wait=True)
            except BaseException:
                pool.shutdown(wait=False, cancel_futures=True)
                raise
        else:
            for path in files:
                accept(copy_one(path))
        manifest = dict(
            schema=CASE_SCHEMA,
            case_id=case_id,
            operator=operator,
            collected_at=utc_now(),
            tool_version=VERSION,
            collection="logical files only",
            files=entries,
        )
        write_json(case / "manifest.json", manifest)
        root = digest(case / "manifest.json")
        record("collection_completed", manifest_sha256=root, files=len(entries))
        with (case / "handling.jsonl").open("x", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
        # Retain these two values OUTSIDE this case if independent tamper detection matters.
        anchor = dict(manifest_sha256=root, handling_sha256=previous)
        write_json(case / "anchor.json", anchor)
        return anchor
    except (Exception, KeyboardInterrupt) as error:
        write_json(case / "INCOMPLETE.json", {"error": str(error), "at": utc_now()})
        raise
