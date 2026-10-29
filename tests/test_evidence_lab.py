import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evidence_lab import collect, digest, timeline, verify
from make_demo import make_demo


class EvidenceLabTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.case = self.root / "source", self.root / "case"
        make_demo(self.source)

    def acquire(self):
        self.anchors = collect(self.source, self.case, operator="Test operator", case_id="SYNTHETIC-001")
        return self.anchors

    def test_source_unchanged_and_binary_copies_verified(self):
        before = {p.name: digest(p) for p in self.source.iterdir()}
        self.acquire()
        self.assertEqual(before, {p.name: digest(p) for p in self.source.iterdir()})
        manifest = verify(self.case, expected_manifest=self.anchors["manifest_sha256"], expected_handling=self.anchors["handling_sha256"])
        self.assertEqual(len(manifest["files"]), 4)
        for entry in manifest["files"]:
            self.assertEqual(entry["sha256"], before[entry["path"]])

    def test_cross_source_timeline_utc_and_provenance(self):
        self.acquire()
        rows = timeline(self.case, self.root / "analysis")
        self.assertEqual(len(rows), 4)
        self.assertEqual([r["action"] for r in rows], ["login", "message", "download", "visit"])
        self.assertEqual(rows[1]["timestamp"], "2026-10-01T09:02:00+00:00")
        self.assertEqual(rows[1]["source_record"], 1)
        self.assertEqual(rows[1]["source_sha256"], digest(self.source / "mobile-export.jsonl"))
        report = json.loads((self.root / "analysis/report.json").read_text())
        self.assertEqual(report["unsupported_files"], ["training-notes.txt"])

    def test_changed_evidence_rejected_before_analysis(self):
        self.acquire()
        (self.case / "evidence/training-notes.txt").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "digest or size"):
            timeline(self.case, self.root / "analysis")
        self.assertFalse((self.root / "analysis").exists())

    def test_handled_keyboard_interrupt_marks_collection_incomplete(self):
        with patch("evidence_lab.digest", side_effect=KeyboardInterrupt):
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
        data = json.loads(manifest.read_text()); data["operator"] = "Rewritten"
        manifest.write_text(json.dumps(data))
        anchor = self.case / "anchor.json"
        data = json.loads(anchor.read_text()); data["manifest_sha256"] = digest(manifest)
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
        path.unlink(); path.symlink_to(self.source / "training-notes.txt")
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
            timeline(self.case, self.case / "analysis")

    def test_naive_timestamp_fails_without_partial_output(self):
        (self.source / "mobile-export.jsonl").write_text(json.dumps(dict(timestamp="2026-10-01T09:02:00", action="message", detail="Synthetic")))
        self.acquire()
        with self.assertRaisesRegex(ValueError, "no timezone"):
            timeline(self.case, self.root / "analysis")
        self.assertFalse((self.root / "analysis").exists())

    def test_csv_formula_neutralised_without_changing_json(self):
        (self.source / "mobile-export.jsonl").write_text(json.dumps(dict(timestamp="2026-10-01T09:02:00Z", action="message", detail="=1+1")))
        self.acquire(); rows = timeline(self.case, self.root / "analysis")
        self.assertEqual(rows[1]["detail"], "=1+1")
        self.assertIn("'=1+1", (self.root / "analysis/timeline.csv").read_text())


if __name__ == "__main__":
    unittest.main()
