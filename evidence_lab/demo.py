"""One-command demonstration and the synthetic scenario generator.

The generator creates deterministic, fictional evidence exports; it never
reads a real profile, phone, mailbox or account.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import webbrowser
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .collect import collect
from .core import ProgressCallback
from .reporting import timeline
from .verify import verify

MBOX_TEXT = (
    "From trainer@example.test Wed Oct  1 09:10:00 2026\n"
    "From: Trainer <trainer@example.test>\n"
    "To: staff@example.test\n"
    "Subject: Training notes follow-up\n"
    "Date: Wed, 01 Oct 2026 09:10:00 +0000\n"
    "Message-ID: <demo-1@example.test>\n"
    "Content-Type: text/plain; charset=us-ascii\n"
    "\n"
    "Fictional message: the training notes are available.\n"
    "\n"
)
DEVICE_LOG = (
    "2026-10-01T08:31:00.000Z lab-device device-agent[4321]: Fictional device sync started\n"
    "2026-10-01T08:32:30.000Z lab-device device-agent[4321]: Fictional device sync completed\n"
)
WEB_LOG = (
    '192.0.2.7 - - [01/Oct/2026:11:46:12 +0000] "GET /training-notes HTTP/1.1" 200 512 "-" "FictionalAgent/1.0"\n'
    '192.0.2.9 - - [01/Oct/2026:11:47:05 +0000] "GET /style.css HTTP/1.1" 200 48 "-" "FictionalAgent/1.0"\n'
)
VISITS_CSV = (
    "timestamp,action,detail\n"
    "2026-10-01T09:08:00Z,visit,https://example.test/dashboard\n"
    "2026-10-01T11:45:00Z,visit,https://example.test/wiki/training\n"
)


def make_demo(root: Path | str, hashset: Path | str | None = None) -> None:
    root = Path(root)
    root.mkdir(exist_ok=False)
    with (root / "cloud-audit.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "action", "detail"])
        writer.writeheader()
        writer.writerows(
            [
                dict(timestamp="2026-10-01T09:03:00Z", action="download", detail="Fictional account downloaded training-notes.txt"),
                dict(
                    timestamp="2026-10-01T09:01:00Z", action="login", detail="Fictional account signed in from documentation IP 192.0.2.7"
                ),
            ]
        )
    (root / "mobile-export.jsonl").write_text(
        json.dumps(dict(timestamp="2026-10-01T10:02:00+01:00", action="message", detail="Fictional message: download the training notes"))
        + "\n"
    )
    db = sqlite3.connect(root / "browser-export.sqlite")
    try:
        db.execute("CREATE TABLE events(timestamp TEXT, action TEXT, detail TEXT)")
        db.execute("INSERT INTO events VALUES (?, ?, ?)", ("2026-10-01T09:04:00Z", "visit", "https://example.test/training-notes"))
        db.execute("CREATE TABLE downloads(timestamp TEXT, action TEXT, detail TEXT)")
        db.execute(
            "INSERT INTO downloads VALUES (?, ?, ?)", ("2026-10-01T09:06:00Z", "download", "Fictional saved copy of the training notes")
        )
        db.commit()
    finally:
        db.close()
    (root / "training-notes.txt").write_text("Synthetic training evidence. No personal data.\n")
    (root / "mail-export.mbox").write_text(MBOX_TEXT)
    (root / "device.log").write_text(DEVICE_LOG)
    (root / "web-server.log").write_text(WEB_LOG)
    with zipfile.ZipFile(root / "archive-export.zip", "x", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("visits.csv", date_time=(2026, 10, 1, 9, 0, 0))
        archive.writestr(info, VISITS_CSV)
    if hashset:
        sha256 = hashlib.sha256((root / "browser-export.sqlite").read_bytes()).hexdigest()
        with Path(hashset).open("x", newline="") as stream:
            sidecar = csv.writer(stream, lineterminator="\n")
            sidecar.writerow(["sha256", "label", "notes"])
            sidecar.writerow([sha256, "synthetic-browser-fixture", "Created by make_demo for the demo flow"])


def run_demo(
    directory: Path | str, *, case_id: str | None = None, open_browser: bool = True, progress: ProgressCallback | None = None
) -> dict[str, str]:
    """Generate a fictional case, collect, verify, analyse and (optionally) open the report."""
    directory = Path(directory)
    if directory.exists():
        raise ValueError(f"Demo directory already exists: {directory}")
    directory.mkdir(parents=True)
    source, case, analysis = directory / "source", directory / "case", directory / "analysis"
    hashset = directory / "hashset.csv"
    case_id = case_id or f"DEMO-{datetime.now(UTC):%Y%m%d}"
    make_demo(source, hashset)
    anchors = collect(source, case, operator="Demo operator", case_id=case_id, progress=progress)
    manifest = verify(case, expected_manifest=anchors["manifest_sha256"], expected_handling=anchors["handling_sha256"])
    rows = timeline(case, analysis, keywords=["training"], session_gap=1800, hashset=hashset, progress=progress)
    report = analysis / "report.html"
    opened = bool(webbrowser.open(report.resolve().as_uri())) if open_browser else False
    return {
        "case_id": case_id,
        "files": str(len(manifest["files"])),
        "records": str(len(rows)),
        "report": str(report),
        "opened": str(opened),
    }
