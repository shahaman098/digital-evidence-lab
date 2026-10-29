"""Educational logical evidence collection. No device access or disk imaging."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import sys
from datetime import datetime, timezone

VERSION = "0.1.0"
ZERO = "0" * 64


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def checked_relative(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts or "\\" in value or str(p) != value:
        raise ValueError(f"Unsafe relative path: {value!r}")
    return p


def case_file(case, relative):
    relative = checked_relative(relative)
    current = case / "evidence"
    if current.is_symlink():
        raise ValueError("Evidence root is a symlink")
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Evidence path contains a symlink")
    return current


def collect(source, case, *, operator, case_id):
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
    events, entries, previous = [], [], ZERO

    def record(action, **detail):
        nonlocal previous
        event = dict(sequence=len(events) + 1, observed_at=utc_now(), operator=operator,
                     action=action, previous_sha256=previous, **detail)
        event["sha256"] = hashlib.sha256(canonical(event)).hexdigest()
        previous = event["sha256"]
        events.append(event)

    record("collection_started", case_id=case_id, tool_version=VERSION)
    try:
        for path in files:
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
            signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if signature(before) != signature(after):
                raise ValueError(f"Source changed during collection: {relative}")
            if digest(target) != h.hexdigest():
                raise ValueError(f"Copy digest mismatch: {relative}")
            entry = dict(path=relative, bytes=before.st_size, sha256=h.hexdigest(),
                         source_mtime_ns=before.st_mtime_ns, collected_at=utc_now())
            entries.append(entry)
            record("file_copied_and_verified", path=relative, bytes=entry["bytes"], sha256_of_copy=entry["sha256"])
        manifest = dict(schema="digital-evidence-lab.case.v1", case_id=case_id, operator=operator,
                        collected_at=utc_now(), tool_version=VERSION, collection="logical files only", files=entries)
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


def verify(case, *, expected_manifest=None, expected_handling=None):
    case = Path(case)
    if (case / "INCOMPLETE.json").exists():
        raise ValueError("Collection is incomplete")
    for name in ("manifest.json", "handling.jsonl", "anchor.json"):
        if (case / name).is_symlink():
            raise ValueError("Case metadata must not be symlinks")
    manifest = json.loads((case / "manifest.json").read_text())
    if manifest["schema"] != "digital-evidence-lab.case.v1" or not manifest["files"]:
        raise ValueError("Invalid manifest")
    anchor = json.loads((case / "anchor.json").read_text())
    manifest_hash = digest(case / "manifest.json")
    if manifest_hash != anchor["manifest_sha256"] or (expected_manifest and manifest_hash != expected_manifest):
        raise ValueError("Manifest digest mismatch")
    previous, events = ZERO, []
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
    for entry in manifest["files"]:
        path = case_file(case, entry["path"])
        if not path.is_file() or path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"]:
            raise ValueError(f"Evidence digest or size mismatch: {entry['path']}")
        matches = [e for e in events if e["action"] == "file_copied_and_verified" and e["path"] == entry["path"]]
        if len(matches) != 1 or matches[0]["sha256_of_copy"] != entry["sha256"]:
            raise ValueError("File and handling log disagree")
    return manifest


def timeline(case, output, *, expected_manifest=None, expected_handling=None):
    case, output = Path(case), Path(output)
    manifest = verify(case, expected_manifest=expected_manifest, expected_handling=expected_handling)
    # Analysis never writes into the evidence or changes case metadata.
    if case.resolve() == output.resolve() or case.resolve() in output.resolve().parents:
        raise ValueError("Analysis output must be outside the case directory")
    rows, unsupported = [], []
    for entry in manifest["files"]:
        path, relative = case_file(case, entry["path"]), entry["path"]
        if path.suffix == ".jsonl":
            records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        elif path.suffix == ".csv":
            with path.open(newline="") as stream:
                records = list(csv.DictReader(stream))
        elif path.suffix == ".sqlite":
            connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                records = [dict(zip(("timestamp", "action", "detail"), row))
                           for row in connection.execute("SELECT timestamp, action, detail FROM events ORDER BY rowid")]
            finally:
                connection.close()
        else:
            unsupported.append(relative)
            continue
        for index, record in enumerate(records, 1):
            date = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
            if date.tzinfo is None:
                raise ValueError(f"Timestamp has no timezone: {relative}, record {index}")
            rows.append(dict(timestamp=date.astimezone(timezone.utc).isoformat(),
                             action=record["action"], detail=record["detail"],
                             source=relative, source_record=index, source_sha256=entry["sha256"]))
    rows.sort(key=lambda r: (r["timestamp"], r["source"], r["source_record"]))
    # Check again so a changed copy cannot silently underpin the completed report.
    verify(case, expected_manifest=expected_manifest, expected_handling=expected_handling)
    output.mkdir(parents=False, exist_ok=False)
    write_json(output / "timeline.json", rows)
    with (output / "timeline.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "action", "detail", "source", "source_record", "source_sha256"], lineterminator="\n")
        writer.writeheader()
        # Spreadsheet exports are intentionally text-neutralised against CSV formulas.
        for row in rows:
            writer.writerow({k: "'" + str(v) if str(v).startswith(("=", "+", "-", "@", "\t", "\r")) else v for k, v in row.items()})
    write_json(output / "report.json", dict(case_id=manifest["case_id"], generated_at=utc_now(),
               tool_version=VERSION, records=len(rows), unsupported_files=unsupported,
               integrity="Verified against case hashes; independent authenticity requires externally retained anchors.",
               source_time_warning="Source timestamps are untrusted claims; ordering does not establish causation.",
               scope="Educational file triage; no disk imaging, deleted recovery, device unlocking or legal admissibility claim."))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("collect")
    p.add_argument("source", type=Path); p.add_argument("case", type=Path)
    p.add_argument("--operator", required=True); p.add_argument("--case-id", required=True)
    for name in ("verify", "timeline"):
        p = commands.add_parser(name); p.add_argument("case", type=Path)
        if name == "timeline": p.add_argument("output", type=Path)
        p.add_argument("--expected-manifest"); p.add_argument("--expected-handling")
    args = vars(parser.parse_args(argv)); command = args.pop("command")
    try:
        result = {"collect": collect, "verify": verify, "timeline": timeline}[command](**args)
    except (ValueError, KeyError, OSError, sqlite3.Error) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "result": result}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
