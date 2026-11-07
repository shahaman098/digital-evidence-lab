"""Timeline orchestration and reporting: JSON, CSV and a self-contained HTML view."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any

from . import analysis
from .core import VERSION, ProgressCallback, case_file, utc_now, write_json
from .parsers import parse_evidence
from .verify import verify

INTEGRITY_NOTE = "Verified against case hashes; independent authenticity requires externally retained anchors."
TIME_WARNING = "Source timestamps are untrusted claims; ordering does not establish causation."
SCOPE_NOTE = "Educational file triage; no disk imaging, deleted recovery, device unlocking or legal admissibility claim."


def _neutral(value: Any) -> Any:
    """Neutralise leading spreadsheet-formula characters in CSV exports."""
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else value


def _offset_timezone(text: str) -> timezone:
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text.strip())
    if not match:
        raise ValueError("--assume-offset must look like +HH:MM")
    sign = 1 if match.group(1) == "+" else -1
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    if delta > timedelta(hours=23, minutes=59):
        raise ValueError("--assume-offset is out of range")
    return timezone(sign * delta)


def _record_sort_key(value: Any) -> tuple[int, Any, str]:
    return (0, value, "") if isinstance(value, int) else (1, 0, str(value))


def _collect_rows(
    case: Path,
    manifest: dict[str, Any],
    *,
    mapping: dict[str, Any] | None = None,
    tz: timezone | None = None,
    year: int | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Parse every supported evidence file into provenance-carrying, UTC-sorted rows."""
    rows: list[dict[str, Any]] = []
    unsupported: list[str] = []
    notes: dict[str, Any] = {}
    total = len(manifest["files"])
    for count, entry in enumerate(manifest["files"], 1):
        relative = entry["path"]
        parsed = parse_evidence(case_file(case, relative), relative, mapping=mapping, assumptions={"tz": tz, "year": year})
        if parsed is None:
            unsupported.append(relative)
            continue
        records, used = parsed
        for index, record in enumerate(records, 1):
            row: dict[str, Any] = {
                "timestamp": record["timestamp"].astimezone(UTC).isoformat(),
                "action": record["action"],
                "detail": record["detail"],
                "source": relative,
                "source_record": record.get("record_id", index),
                "source_sha256": entry["sha256"],
            }
            if record.get("extra"):
                row["extra"] = record["extra"]
            rows.append(row)
        notes[relative] = used
        if progress:
            progress(count, total, f"parsed {relative}")
    rows.sort(key=lambda row: (row["timestamp"], row["source"], _record_sort_key(row["source_record"])))
    return rows, unsupported, notes


def _load_hashset(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        names = [name.strip().lower() for name in (reader.fieldnames or [])]
        if "sha256" not in names:
            raise ValueError("Hash set needs a sha256 column")
        known: dict[str, dict[str, Any]] = {}
        for row in reader:
            value = (row.get("sha256") or "").strip().lower()
            if not value:
                continue
            entry = known.setdefault(value, {"labels": [], "notes": ""})
            label = (row.get("label") or row.get("Label") or "known").strip()
            if label and label not in entry["labels"]:
                entry["labels"].append(label)
            note = (row.get("notes") or "").strip()
            if note and note not in entry["notes"]:
                entry["notes"] = f"{entry['notes']}; {note}".strip("; ")
        return known


def _classify(manifest: dict[str, Any], hashset: Path | None) -> dict[str, Any] | None:
    if hashset is None:
        return None
    known = _load_hashset(hashset)
    matched = []
    for entry in manifest["files"]:
        hit = known.get(str(entry["sha256"]).lower())
        if hit:
            matched.append({"path": entry["path"], "sha256": entry["sha256"], "labels": hit["labels"], "notes": hit["notes"]})
    return {
        "hashset": str(hashset),
        "hashset_entries": len(known),
        "matched": matched,
        "unmatched_case_files": len(manifest["files"]) - len(matched),
    }


def timeline(
    case: Path | str,
    output: Path | str,
    *,
    expected_manifest: str | None = None,
    expected_handling: str | None = None,
    jobs: int = 1,
    mapping_path: Path | str | None = None,
    keywords: list[str] | None = None,
    regex: bool = False,
    session_gap: int | None = None,
    hashset: Path | str | None = None,
    html: bool = True,
    assume_offset: str | None = None,
    assume_year: int | None = None,
    progress: ProgressCallback | None = None,
) -> list[dict[str, Any]]:
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    case, output = Path(case), Path(output)
    manifest = verify(case, expected_manifest=expected_manifest, expected_handling=expected_handling, jobs=jobs)
    # Analysis never writes into the evidence or changes case metadata.
    if case.resolve() == output.resolve() or case.resolve() in output.resolve().parents:
        raise ValueError("Analysis output must be outside the case directory")
    mapping = None
    if mapping_path:
        mapping = json.loads(Path(mapping_path).read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or not all(isinstance(rule, dict) for rule in mapping.values()):
            raise ValueError("Mapping file must be a JSON object of objects")
    assumptions: dict[str, Any] = {}
    tz = None
    if assume_offset and assume_year:
        tz = _offset_timezone(assume_offset)
        assumptions["syslog_rfc3164"] = {"assume_offset": assume_offset, "assume_year": assume_year}
    elif assume_offset or assume_year:
        raise ValueError("--assume-offset and --assume-year must be provided together")

    rows, unsupported, mapping_notes = _collect_rows(case, manifest, mapping=mapping, tz=tz, year=assume_year, progress=progress)
    # Check again so a changed copy cannot silently underpin the completed report.
    verify(case, expected_manifest=expected_manifest, expected_handling=expected_handling, jobs=jobs)
    output.mkdir(parents=False, exist_ok=False)
    write_json(output / "timeline.json", rows)
    _write_timeline_csv(output / "timeline.csv", rows)

    analysis_out: dict[str, Any] = {
        "summary": analysis.summarize(rows),
        "entities": analysis.entities(rows),
        "histogram": analysis.histogram(rows),
    }
    if keywords:
        analysis_out["keywords"] = analysis.keyword_results(rows, keywords, regex=regex)
    if session_gap:
        analysis_out["sessions"] = analysis.sessions(rows, session_gap)
    report = {
        "schema": "digital-evidence-lab.report.v2",
        "case_id": manifest["case_id"],
        "generated_at": utc_now(),
        "tool_version": VERSION,
        "records": len(rows),
        "unsupported_files": unsupported,
        "integrity": INTEGRITY_NOTE,
        "source_time_warning": TIME_WARNING,
        "scope": SCOPE_NOTE,
        "field_mappings": mapping_notes,
        "timestamp_assumptions": assumptions,
        "file_classifications": _classify(manifest, Path(hashset) if hashset else None),
        "analysis": analysis_out,
    }
    write_json(output / "report.json", report)
    if html:
        (output / "report.html").write_text(_html_report(report, rows), encoding="utf-8")
    return rows


def _write_timeline_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = ["timestamp", "action", "detail", "source", "source_record", "source_sha256"]
    if any("extra" in row for row in rows):
        fields.append("extra")
    with path.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", restval="")
        writer.writeheader()
        # Spreadsheet exports are intentionally text-neutralised against CSV formulas.
        for row in rows:
            out = {key: _neutral(value) for key, value in row.items()}
            if "extra" in fields:
                out["extra"] = json.dumps(row["extra"], ensure_ascii=False, sort_keys=True) if "extra" in row else ""
            writer.writerow(out)


# ------------------------------------------------------------------ search


def search(
    case: Path | str,
    query: str,
    *,
    regex: bool = False,
    jobs: int = 1,
    mapping_path: Path | str | None = None,
    expected_manifest: str | None = None,
    expected_handling: str | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    manifest = verify(case, expected_manifest=expected_manifest, expected_handling=expected_handling, jobs=jobs)
    mapping = None
    if mapping_path:
        mapping = json.loads(Path(mapping_path).read_text(encoding="utf-8"))
        if not isinstance(mapping, dict) or not all(isinstance(rule, dict) for rule in mapping.values()):
            raise ValueError("Mapping file must be a JSON object of objects")
    rows, unsupported, _ = _collect_rows(Path(case), manifest, mapping=mapping, progress=progress)
    result = analysis.search_rows(rows, query, regex=regex)
    return {
        "query": query,
        "regex": regex,
        "records_searched": len(rows),
        "unsupported_files": unsupported,
        "total_hits": result["count"],
        "matches": result["matches"],
        "matches_truncated": result["matches_truncated"],
    }


# -------------------------------------------------------------- HTML report


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _svg_bars(title: str, items: list[tuple[Any, int]], cap: int = 20) -> str:
    items = [(str(label), count) for label, count in items][:cap]
    if not items:
        return ""
    left, span, row_height, top = 170, 380, 24, 26
    height = top + row_height * len(items) + (20 if len(items) == cap else 0)
    peak = max(count for _, count in items) or 1
    parts = [
        f'<svg width="640" height="{height}" role="img" aria-label="{escape(title)}">',
        f'<text x="0" y="14" class="title">{escape(title)}</text>',
    ]
    y = top
    for label, count in items:
        width = max(2, round(span * count / peak))
        parts.append(f'<text x="{left - 8}" y="{y + 4}" text-anchor="end" class="lbl">{escape(_clip(label, 26))}</text>')
        parts.append(f'<rect x="{left}" y="{y - 8}" width="{width}" height="14" rx="2"></rect>')
        parts.append(f'<text x="{left + width + 6}" y="{y + 4}" class="val">{count}</text>')
        y += row_height
    if len(items) == cap:
        parts.append(f'<text x="0" y="{y + 4}" class="lbl">showing top {cap}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _table(headers: Sequence[str], rows_of_cells: Iterable[Sequence[Any]]) -> str:
    parts = ["<table><thead><tr>", *[f"<th>{escape(header)}</th>" for header in headers], "</tr></thead><tbody>"]
    for cells in rows_of_cells:
        parts.append("<tr>")
        parts.extend(f"<td>{cell}</td>" for cell in cells)
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _mono(value: Any) -> str:
    return f"<code>{escape(str(value))}</code>"


def _html_report(report: dict[str, Any], rows: list[dict[str, Any]], table_cap: int = 500) -> str:
    summary = report["analysis"]["summary"]
    chips = "".join(
        f"<span>{escape(_clip(f'{key}: {value}', 60))}</span>"
        for key, value in (
            ("case", report["case_id"]),
            ("records", summary["records"]),
            ("files", summary["files"]),
            ("unsupported", len(report["unsupported_files"])),
            ("span", f"{summary['first'][:19] if summary['first'] else '—'} → {summary['last'][:19] if summary['last'] else '—'}"),
        )
    )
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>Digital Evidence Lab — analysis of {escape(report['case_id'])}</title>",
        "<style>",
        "body{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;margin:2rem auto;max-width:62rem;padding:0 1rem;color:#1c2733;background:#fafbfc}",
        "h1{font-size:1.4rem;margin-bottom:.2rem}h2{font-size:1.05rem;margin-top:2rem;border-bottom:1px solid #d7dee6;padding-bottom:.3rem}",
        ".chips span{display:inline-block;background:#e8effa;color:#1d4fa1;border-radius:1rem;padding:.15rem .7rem;margin:0 .4rem .4rem 0;font-size:.85rem}",
        "table{border-collapse:collapse;width:100%;font-size:.83rem;margin:.5rem 0}th,td{border:1px solid #d7dee6;padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:#eef2f7}",
        "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem}",
        "svg{margin:.5rem 0}svg rect{fill:#3567b1}svg .title{font-weight:600;font-size:13px;fill:#1c2733}svg .lbl{font-size:11px;fill:#4a5a6a}svg .val{font-size:11px;fill:#1c2733}",
        ".note{color:#5a6a7a;font-size:.8rem}",
        "footer{margin-top:2.5rem;border-top:1px solid #d7dee6;padding-top:1rem;font-size:.8rem;color:#5a6a7a}",
        "</style></head><body>",
        "<h1>Digital Evidence Lab — analysis report</h1>",
        f"<p class='note'>Generated {escape(report['generated_at'])} by digital-evidence-lab {escape(report['tool_version'])}. "
        "This page is a convenience view; timeline.json remains the data of record.</p>",
        f"<p class='chips'>{chips}</p>",
        "<h2>Records per hour (UTC)</h2>",
        _svg_bars(
            "records per hour", [(item["hour"][11:16] if item["hour"] else "", item["records"]) for item in report["analysis"]["histogram"]]
        ),
        "<h2>Records per source file</h2>",
        _svg_bars("records per source", list(summary["per_source"].items())),
        "<h2>Records per action</h2>",
        _svg_bars("records per action", list(summary["per_action"].items())),
    ]
    keywords = report["analysis"].get("keywords")
    if keywords:
        parts.append("<h2>Keyword search</h2>")
        parts.append(
            "<p class='note'>Literal/regex text matches over action, detail and extra fields. "
            "A hit shows the term appears — not why, and not that it matters.</p>"
        )
        for result in keywords:
            parts.append(f"<h3>{escape(result['term'])} — {result['count']} hit(s)</h3>")
            parts.append(
                _table(
                    ("timestamp", "source", "record", "field", "excerpt"),
                    [
                        (escape(m["timestamp"]), _mono(m["source"]), _mono(m["source_record"]), escape(m["field"]), escape(m["excerpt"]))
                        for m in result["matches"]
                    ],
                )
            )
    entities = report["analysis"].get("entities") or {}
    if entities:
        parts.extend(
            (
                "<h2>Extracted entities</h2>",
                "<p class='note'>Regex-based extraction; domains and IPs may be incidental strings, "
                "and one value can appear under several kinds.</p>",
            )
        )
        for kind in ("ipv4", "email", "url", "domain", "sha256"):
            if not entities.get(kind):
                continue
            parts.append(f"<h3>{escape(kind)}</h3>")
            parts.append(
                _table(
                    ("value", "count", "first seen", "last seen", "examples"),
                    [
                        (
                            escape(e["value"]),
                            e["count"],
                            escape(e["first_seen"]),
                            escape(e["last_seen"]),
                            _mono(f"{e['examples'][0]['source']}#{e['examples'][0]['source_record']}"),
                        )
                        for e in entities[kind]
                    ],
                )
            )
    session_out = report["analysis"].get("sessions")
    if session_out:
        parts.append(f"<h2>Sessions (gap &gt; {escape(str(session_out['gap_seconds']))}s)</h2>")
        parts.append(
            _table(("start", "end", "records"), [(escape(s["start"]), escape(s["end"]), s["records"]) for s in session_out["sessions"]])
        )
        if session_out["largest_gaps"]:
            parts.append("<p class='note'>Largest gaps between consecutive records:</p>")
            parts.append(
                _table(
                    ("after", "before", "seconds"),
                    [(escape(g["after"]), escape(g["before"]), f"{g['seconds']:.0f}") for g in session_out["largest_gaps"]],
                )
            )
    classifications = report.get("file_classifications")
    if classifications and classifications["matched"]:
        parts.append("<h2>Hash-set classifications</h2>")
        parts.append(
            _table(
                ("path", "labels", "notes"),
                [(_mono(m["path"]), escape(", ".join(m["labels"])), escape(m["notes"])) for m in classifications["matched"]],
            )
        )
    parts.append("<h2>Timeline</h2>")
    shown = rows[:table_cap]
    parts.append(
        _table(
            ("timestamp", "action", "source", "record", "detail"),
            [
                (
                    escape(r["timestamp"]),
                    escape(r["action"]),
                    _mono(r["source"]),
                    _mono(r["source_record"]),
                    escape(_clip(r["detail"], 220)),
                )
                for r in shown
            ],
        )
    )
    if len(rows) > table_cap:
        parts.append(
            f"<p class='note'>Table truncated to the first {table_cap} of {len(rows)} records; see timeline.json for the full set.</p>"
        )
    if report["unsupported_files"]:
        parts.append("<h2>Unsupported files (listed, not analysed)</h2><ul>")
        parts.extend(f"<li>{_mono(name)}</li>" for name in report["unsupported_files"])
        parts.append("</ul>")
    parts.extend(
        (
            "<footer>",
            f"<p>{escape(report['integrity'])}</p>",
            f"<p>{escape(report['source_time_warning'])}</p>",
            f"<p>{escape(report['scope'])}</p>",
            "</footer></body></html>",
        )
    )
    return "".join(parts)
