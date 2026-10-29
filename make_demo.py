"""Create deterministic, fictional evidence exports; never reads a real profile."""
import csv
import json
from pathlib import Path
import sqlite3
import sys


def make_demo(root):
    root = Path(root)
    root.mkdir(exist_ok=False)
    with (root / "cloud-audit.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "action", "detail"])
        writer.writeheader()
        writer.writerows([
            dict(timestamp="2026-10-01T09:03:00Z", action="download", detail="Fictional account downloaded training-notes.txt"),
            dict(timestamp="2026-10-01T09:01:00Z", action="login", detail="Fictional account signed in from documentation IP 192.0.2.7"),
        ])
    (root / "mobile-export.jsonl").write_text(json.dumps(dict(timestamp="2026-10-01T10:02:00+01:00", action="message", detail="Fictional message: download the training notes")) + "\n")
    db = sqlite3.connect(root / "browser-export.sqlite")
    try:
        db.execute("CREATE TABLE events(timestamp TEXT, action TEXT, detail TEXT)")
        db.execute("INSERT INTO events VALUES (?, ?, ?)", ("2026-10-01T09:04:00Z", "visit", "https://example.test/training-notes"))
        db.commit()
    finally:
        db.close()
    (root / "training-notes.txt").write_text("Synthetic training evidence. No personal data.\n")


if __name__ == "__main__":
    make_demo(sys.argv[1])
