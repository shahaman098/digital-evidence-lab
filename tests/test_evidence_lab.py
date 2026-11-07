import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_lab import VERSION, collect, digest, search, timeline, ui, verify
from evidence_lab.cli import main
from evidence_lab.demo import run_demo
from evidence_lab.ui import ProgressRenderer, colorize, progress_bar
from make_demo import make_demo


class EvidenceLabTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.case = self.root / "source", self.root / "case"
        make_demo(self.source)

    def acquire(self, **kwargs):
        self.anchors = collect(self.source, self.case, operator="Test operator", case_id="SYNTHETIC-001", **kwargs)
        return self.anchors

    def analyse(self, name="analysis", **kwargs):
        return timeline(self.case, self.root / name, **kwargs)

    def test_source_unchanged_and_binary_copies_verified(self):
        before = {p.name: digest(p) for p in self.source.iterdir()}
        self.acquire()
        self.assertEqual(before, {p.name: digest(p) for p in self.source.iterdir()})
        manifest = verify(self.case, expected_manifest=self.anchors["manifest_sha256"], expected_handling=self.anchors["handling_sha256"])
        self.assertEqual(len(manifest["files"]), 8)
        for entry in manifest["files"]:
            self.assertEqual(entry["sha256"], before[entry["path"]])

    def test_cross_source_timeline_utc_and_provenance(self):
        self.acquire()
        rows = self.analyse()
        self.assertEqual(len(rows), 12)
        self.assertEqual(
            [r["action"] for r in rows],
            ["device-agent", "device-agent", "login", "message", "download", "visit", "download", "visit", "email", "visit", "GET", "GET"],
        )
        self.assertEqual(rows[3]["timestamp"], "2026-10-01T09:02:00+00:00")
        self.assertEqual(rows[3]["source_record"], 1)
        self.assertEqual(rows[3]["source_sha256"], digest(self.source / "mobile-export.jsonl"))
        report = json.loads((self.root / "analysis/report.json").read_text())
        self.assertEqual(report["unsupported_files"], ["training-notes.txt"])
        self.assertEqual(report["schema"], "digital-evidence-lab.report.v2")

    def test_changed_evidence_rejected_before_analysis(self):
        self.acquire()
        (self.case / "evidence/training-notes.txt").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "digest or size"):
            self.analyse()
        self.assertFalse((self.root / "analysis").exists())

    def test_handled_keyboard_interrupt_marks_collection_incomplete(self):
        with patch("evidence_lab.collect.digest", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.acquire()
        self.assertTrue((self.case / "INCOMPLETE.json").is_file())
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verify(self.case)

    def test_missing_and_extra_files_rejected(self):
        self.acquire()
        (self.case / "evidence/extra.txt").write_text("extra")
        with self.assertRaisesRegex(ValueError, "inventory"):
            verify(self.case)
        (self.case / "evidence/extra.txt").unlink()
        (self.case / "evidence/training-notes.txt").unlink()
        with self.assertRaisesRegex(ValueError, "inventory"):
            verify(self.case)

    def test_log_tampering_rejected(self):
        self.acquire()
        path = self.case / "handling.jsonl"
        path.write_text(path.read_text().replace("Test operator", "Someone else", 1))
        with self.assertRaisesRegex(ValueError, "event digest"):
            verify(self.case)

    def test_log_truncation_rejected(self):
        self.acquire()
        path = self.case / "handling.jsonl"
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "anchor"):
            verify(self.case)

    def test_external_anchor_detects_rewritten_manifest_and_local_anchor(self):
        self.acquire()
        manifest = self.case / "manifest.json"
        data = json.loads(manifest.read_text())
        data["operator"] = "Rewritten"
        manifest.write_text(json.dumps(data))
        anchor = self.case / "anchor.json"
        data = json.loads(anchor.read_text())
        data["manifest_sha256"] = digest(manifest)
        anchor.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Manifest digest"):
            verify(self.case, expected_manifest=self.anchors["manifest_sha256"])

    def test_symlink_source_rejected_before_case_created(self):
        (self.source / "linked").symlink_to(self.source / "training-notes.txt")
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            self.acquire()
        self.assertFalse(self.case.exists())

    def test_symlink_evidence_rejected(self):
        self.acquire()
        path = self.case / "evidence/training-notes.txt"
        path.unlink()
        path.symlink_to(self.source / "training-notes.txt")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            verify(self.case)

    def test_collection_refuses_overlap_and_existing_case(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            collect(self.source, self.source / "case", operator="Test", case_id="TEST")
        self.acquire()
        with self.assertRaises(FileExistsError):
            self.acquire()

    def test_analysis_never_writes_into_case(self):
        self.acquire()
        with self.assertRaisesRegex(ValueError, "outside"):
            self.analyse(name="case/analysis")

    def test_naive_timestamp_fails_without_partial_output(self):
        (self.source / "mobile-export.jsonl").write_text(
            json.dumps(dict(timestamp="2026-10-01T09:02:00", action="message", detail="Synthetic"))
        )
        self.acquire()
        with self.assertRaisesRegex(ValueError, "no timezone"):
            self.analyse()
        self.assertFalse((self.root / "analysis").exists())

    def test_csv_formula_neutralised_without_changing_json(self):
        (self.source / "mobile-export.jsonl").write_text(
            json.dumps(dict(timestamp="2026-10-01T09:02:00Z", action="message", detail="=1+1"))
        )
        self.acquire()
        rows = self.analyse()
        self.assertEqual(rows[3]["detail"], "=1+1")
        self.assertIn("'=1+1", (self.root / "analysis/timeline.csv").read_text())

    # ---------------------------------------------------------- v0.2 parsers

    def test_sqlite_multi_table_discovery(self):
        self.acquire()
        rows = self.analyse()
        by_table = {(r["source"], str(r["source_record"])): r for r in rows if r["source"].endswith(".sqlite")}
        self.assertEqual(by_table[("browser-export.sqlite", "events#1")]["action"], "visit")
        self.assertEqual(by_table[("browser-export.sqlite", "downloads#1")]["action"], "download")

    def test_mbox_email_parser(self):
        self.acquire()
        rows = self.analyse()
        mail = next(r for r in rows if r["source"] == "mail-export.mbox")
        self.assertEqual(mail["action"], "email")
        self.assertEqual(mail["timestamp"], "2026-10-01T09:10:00+00:00")
        self.assertIn("trainer@example.test", mail["extra"]["from"])
        self.assertEqual(mail["detail"], "Training notes follow-up")

    def test_syslog_rfc5424_parsed(self):
        self.acquire()
        rows = self.analyse()
        syncs = [r for r in rows if r["source"] == "device.log"]
        self.assertEqual([r["action"] for r in syncs], ["device-agent", "device-agent"])
        self.assertEqual(syncs[0]["timestamp"], "2026-10-01T08:31:00+00:00")
        self.assertEqual(syncs[0]["extra"]["host"], "lab-device")

    def test_syslog_rfc3164_requires_declared_assumptions(self):
        (self.source / "legacy.log").write_text("Oct  1 09:00:00 legacy-host cron[99]: Fictional legacy job ran\n")
        self.acquire()
        with self.assertRaisesRegex(ValueError, "assume-offset"):
            self.analyse("no-assumptions")
        rows = self.analyse("with-assumptions", assume_offset="+00:00", assume_year=2026)
        legacy = next(r for r in rows if r["source"] == "legacy.log")
        self.assertEqual(legacy["timestamp"], "2026-10-01T09:00:00+00:00")
        self.assertEqual(legacy["action"], "cron")
        report = json.loads((self.root / "with-assumptions/report.json").read_text())
        self.assertEqual(report["timestamp_assumptions"]["syslog_rfc3164"]["assume_year"], 2026)

    def test_apache_combined_log(self):
        self.acquire()
        rows = self.analyse()
        hits = [r for r in rows if r["source"] == "web-server.log"]
        self.assertEqual([r["action"] for r in hits], ["GET", "GET"])
        self.assertEqual(hits[0]["timestamp"], "2026-10-01T11:46:12+00:00")
        self.assertEqual(hits[0]["extra"]["client_ip"], "192.0.2.7")
        self.assertEqual(hits[0]["extra"]["status"], "200")

    def test_zip_member_provenance(self):
        self.acquire()
        rows = self.analyse()
        visits = [r for r in rows if r["source"] == "archive-export.zip"]
        self.assertEqual([str(r["source_record"]) for r in visits], ["visits.csv#1", "visits.csv#2"])
        self.assertEqual(visits[0]["extra"]["member"], "visits.csv")
        self.assertEqual(visits[1]["timestamp"], "2026-10-01T11:45:00+00:00")

    def test_gzip_member_parsed(self):
        payload = b"timestamp,action,detail\n2026-10-01T10:30:00Z,metric,Fictional metric value\n"
        (self.source / "metrics.csv.gz").write_bytes(gzip.compress(payload))
        self.acquire()
        rows = self.analyse()
        metric = next(r for r in rows if r["source"] == "metrics.csv.gz")
        self.assertEqual(metric["action"], "metric")
        self.assertEqual(metric["timestamp"], "2026-10-01T10:30:00+00:00")

    def test_mapping_override_exact_and_glob(self):
        (self.source / "calls.csv").write_text("when,direction,note\n2026-10-01T09:20:00Z,in,Fictional call\n")
        (self.source / "pings.ndjson").write_text(json.dumps(dict(ts="2026-10-01T09:21:00Z", event="ping", msg="Fictional ping")) + "\n")
        mapping = self.root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {
                    "calls.csv": {"timestamp": "when", "action": "direction", "detail": "note"},
                    "*.ndjson": {"timestamp": "ts", "action": "event", "detail": "msg"},
                }
            )
        )
        self.acquire()
        rows = self.analyse(mapping_path=mapping)
        self.assertEqual(next(r for r in rows if r["source"] == "calls.csv")["action"], "in")
        self.assertEqual(next(r for r in rows if r["source"] == "pings.ndjson")["action"], "ping")
        report = json.loads((self.root / "analysis/report.json").read_text())
        self.assertEqual(report["field_mappings"]["calls.csv"]["strategy"], "mapping file")

    def test_auto_detected_mapping_recorded(self):
        self.acquire()
        self.analyse()
        report = json.loads((self.root / "analysis/report.json").read_text())
        self.assertEqual(report["field_mappings"]["cloud-audit.csv"]["timestamp"], "timestamp")
        self.assertEqual(report["field_mappings"]["cloud-audit.csv"]["strategy"], "auto-detected")

    # ---------------------------------------------------------- v0.2 analysis

    def test_keyword_search_counts_and_provenance(self):
        self.acquire()
        self.analyse(keywords=["training"])
        report = json.loads((self.root / "analysis/report.json").read_text())
        result = report["analysis"]["keywords"][0]
        self.assertEqual(result["term"], "training")
        self.assertGreaterEqual(result["count"], 5)
        match = result["matches"][0]
        for key in ("timestamp", "source", "source_record", "field", "excerpt"):
            self.assertIn(key, match)

    def test_keyword_regex_mode(self):
        self.acquire()
        self.analyse(keywords=[r"192\.0\.2\.\d"], regex=True)
        report = json.loads((self.root / "analysis/report.json").read_text())
        self.assertGreaterEqual(report["analysis"]["keywords"][0]["count"], 2)

    def test_session_gap_analysis(self):
        self.acquire()
        self.analyse(session_gap=1800)
        sessions = json.loads((self.root / "analysis/report.json").read_text())["analysis"]["sessions"]
        self.assertEqual(sessions["count"], 2)
        self.assertEqual([s["records"] for s in sessions["sessions"]], [9, 3])
        self.assertEqual(sessions["largest_gaps"][0]["seconds"], 9300.0)

    def test_entity_extraction(self):
        self.acquire()
        self.analyse()
        entities = json.loads((self.root / "analysis/report.json").read_text())["analysis"]["entities"]
        self.assertIn("192.0.2.7", [e["value"] for e in entities["ipv4"]])
        self.assertIn("https://example.test/training-notes", [e["value"] for e in entities["url"]])
        self.assertIn("trainer@example.test", [e["value"] for e in entities["email"]])

    def test_hashset_classification(self):
        self.acquire()
        hashset = self.root / "hashset.csv"
        hashset.write_text(f"sha256,label,notes\n{digest(self.source / 'browser-export.sqlite')},synthetic-fixture,Demo label\n")
        self.analyse(hashset=hashset)
        classified = json.loads((self.root / "analysis/report.json").read_text())["file_classifications"]
        self.assertEqual(classified["matched"][0]["path"], "browser-export.sqlite")
        self.assertEqual(classified["matched"][0]["labels"], ["synthetic-fixture"])
        self.assertEqual(classified["unmatched_case_files"], 7)

    def test_html_report_self_contained(self):
        (self.source / "mobile-export.jsonl").write_text(
            json.dumps(dict(timestamp="2026-10-01T09:02:00Z", action="message", detail="<b>Fictional</b> message"))
        )
        self.acquire()
        self.analyse()
        page = (self.root / "analysis/report.html").read_text()
        self.assertIn("<svg", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("<b>Fictional", page)
        self.assertIn("&lt;b&gt;Fictional", page)

    # ---------------------------------------------------------- v0.2 plumbing

    def test_parallel_jobs_match_sequential(self):
        self.acquire(jobs=1)
        sequential = [(e["path"], e["sha256"]) for e in verify(self.case)["files"]]
        other = self.root / "case-parallel"
        collect(self.source, other, operator="Test operator", case_id="SYNTHETIC-001", jobs=4)
        parallel = [(e["path"], e["sha256"]) for e in verify(other, jobs=4)["files"]]
        self.assertEqual(sequential, parallel)

    def test_search_finds_provenance(self):
        self.acquire()
        result = search(self.case, "training")
        self.assertGreaterEqual(result["total_hits"], 5)
        self.assertGreaterEqual(result["records_searched"], 12)
        self.assertIn("source", result["matches"][0])

    def test_version_flag(self):
        self.assertEqual(VERSION, "0.3.0")
        with self.assertRaises(SystemExit) as exited:
            main(["--version"])
        self.assertEqual(exited.exception.code, 0)

    def test_cli_end_to_end(self):
        self.acquire()
        self.assertEqual(main(["verify", str(self.case)]), 0)
        self.assertEqual(main(["search", str(self.case), "training"]), 0)
        self.assertEqual(
            main(["timeline", str(self.case), str(self.root / "cli-analysis"), "--keywords", "training", "--session-gap", "1800"]), 0
        )
        self.assertTrue((self.root / "cli-analysis/report.html").is_file())

    # ------------------------------------------------- v0.3 polish & plumbing

    def test_collect_reports_progress_counts(self):
        seen = []
        self.acquire(progress=lambda done, total, message: seen.append((done, total, message)))
        self.assertEqual(seen[-1][:2], (8, 8))
        self.assertTrue(all(total == 8 for _, total, _ in seen))
        self.assertIn("collected", seen[-1][2])

    def test_demo_command_runs_end_to_end(self):
        demo_dir = self.root / "demo"
        self.assertEqual(main(["demo", "--dir", str(demo_dir), "--no-open"]), 0)
        self.assertTrue((demo_dir / "case/manifest.json").is_file())
        self.assertTrue((demo_dir / "case/anchor.json").is_file())
        self.assertTrue((demo_dir / "analysis/report.html").is_file())
        self.assertTrue((demo_dir / "hashset.csv").is_file())

    def test_demo_refuses_existing_directory(self):
        demo_dir = self.root / "demo-again"
        self.assertEqual(main(["demo", "--dir", str(demo_dir), "--no-open"]), 0)
        with self.assertRaisesRegex(ValueError, "already exists"):
            run_demo(demo_dir, open_browser=False)

    def test_search_honours_mapping(self):
        # Auto-detection cannot read this timestamp format; the mapping file can.
        (self.source / "calls.csv").write_text("when,direction,note\n01/10/2026 09:00 +0000,in,Fictional call about training\n")
        self.acquire()
        mapping = self.root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {"calls.csv": {"timestamp": "when", "timestamp_format": "%d/%m/%Y %H:%M %z", "action": "direction", "detail": "note"}}
            )
        )
        with self.assertRaisesRegex(ValueError, "Unreadable timestamp"):
            search(self.case, "training")
        result = search(self.case, "training", mapping_path=mapping)
        self.assertGreaterEqual(result["total_hits"], 1)
        self.assertEqual(result["unsupported_files"], ["training-notes.txt"])

    def test_python_dash_m_entry_point(self):
        completed = subprocess.run([sys.executable, "-m", "evidence_lab", "--version"], capture_output=True, text=True, check=True)
        self.assertIn("0.3.0", completed.stdout)

    def test_progress_and_colour_helpers(self):
        self.assertEqual(len(progress_bar(1, 4)), 24)
        self.assertEqual(progress_bar(2, 4).count("█"), 12)
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(colorize("x", ui.GREEN), "x")
        self.assertTrue(colorize("x", ui.GREEN, enabled=True).startswith("\x1b["))
        buffer = io.StringIO()
        renderer = ProgressRenderer(buffer, force=True)
        renderer(4, 8, "halfway")
        rendered = buffer.getvalue()
        self.assertIn("50%", rendered)
        self.assertIn("halfway", rendered)
        renderer.finish()
        quiet = ProgressRenderer(io.StringIO())
        quiet(1, 2, "silent")
        self.assertEqual(quiet.stream.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
