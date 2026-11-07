"""Evidence format parsers.

Each parser returns ``(records, notes)`` where records are canonical dicts::

    {"record_id": int|str, "timestamp": aware datetime,
     "action": str, "detail": str, "extra": dict}

``record_id`` preserves the source ordering identity (line/table/member);
provenance fields (source file, digest) are attached by the caller. Parsing is
educational and text-oriented: it is not hardened against hostile input.
"""

from __future__ import annotations

import csv
import fnmatch
import gzip
import io
import json
import re
import sqlite3
import zipfile
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, TextIO

Record = dict[str, Any]
ParseResult = tuple[list[Record], dict[str, Any]]
ParserFn = Callable[..., ParseResult | None]

TIMESTAMP_KEYS = ("timestamp", "time", "datetime", "date", "ts", "created", "created_at", "recorded_at", "when")
ACTION_KEYS = ("action", "event", "type", "operation", "kind", "activity", "category")
DETAIL_KEYS = ("detail", "description", "message", "msg", "summary", "notes", "note", "text", "body", "comment")

RFC3164 = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-.]+?)(?:\[(\d+)\])?:\s*(.*)$")
APACHE = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?\s*$')
APACHE_TIME = re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})")
SYSLOG_PREFIX = re.compile(r"^(?:<\d{1,3}>\d\s+)?")
MONTHS = {name: index for index, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


# ---------------------------------------------------------------- timestamps


def parse_iso(text: str, relative: str, index: int) -> datetime:
    """Parse an ISO-8601-ish string; naive values are refused, not assumed."""
    value = str(text).strip()
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Unreadable timestamp: {relative}, record {index} ({value!r})") from error
    if date.tzinfo is None:
        raise ValueError(f"Timestamp has no timezone: {relative}, record {index}")
    return date


def parse_timestamp(value: Any, relative: str, index: int, fmt: str | None = None) -> datetime:
    if value is None or not str(value).strip():
        raise ValueError(f"Missing timestamp: {relative}, record {index}")
    if not fmt:
        return parse_iso(str(value), relative, index)
    try:
        date = datetime.strptime(str(value).strip(), fmt)
    except ValueError as error:
        raise ValueError(f"Unreadable timestamp: {relative}, record {index} ({value!r})") from error
    if date.tzinfo is None:
        raise ValueError(f"Timestamp has no timezone: {relative}, record {index}")
    return date


def _looks_aware(value: Any) -> bool:
    if value is None:
        return False
    try:
        return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


# ------------------------------------------------------------ field mapping


def pick_mapping(relative: str, mapping: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the explicit rule for this file (exact name first, then glob), or None."""
    if not mapping:
        return None
    for pattern, rule in mapping.items():
        if pattern == relative:
            return _checked_rule(pattern, rule)
    for pattern, rule in mapping.items():
        if fnmatch.fnmatchcase(relative, pattern):
            return _checked_rule(pattern, rule)
    return None


def _checked_rule(pattern: str, rule: Any) -> dict[str, Any]:
    if not isinstance(rule, dict) or not rule.get("timestamp"):
        raise ValueError(f"Mapping {pattern!r} must be an object with a timestamp field")
    return {**rule, "strategy": "mapping file"}


def _auto_mapping(columns: list[str], sample: Sequence[Any]) -> dict[str, Any] | None:
    lower: dict[str, str] = {}
    for column in columns:
        if column:
            lower.setdefault(str(column).strip().lower(), column)
    timestamp = next((lower[key] for key in TIMESTAMP_KEYS if key in lower), None)
    action = next((lower[key] for key in ACTION_KEYS if key in lower), None)
    detail = next((lower[key] for key in DETAIL_KEYS if key in lower and lower[key] != action), None)
    if timestamp is None:
        for column in columns:
            if sample and sum(1 for row in sample if _looks_aware((row or {}).get(column))) / len(sample) >= 0.6:
                timestamp = column
                break
    if timestamp is None:
        return None
    return {
        "timestamp": timestamp,
        "action": action,
        "detail": detail,
        "extra": [c for c in columns if c not in (timestamp, action, detail)],
        "strategy": "auto-detected",
    }


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _record_from_rule(row: dict[str, Any], rule: dict[str, Any], relative: str, index: int) -> Record:
    date = parse_timestamp(row.get(rule["timestamp"]), relative, index, rule.get("timestamp_format"))
    action = _text(row.get(rule["action"])) if rule.get("action") else "record"
    detail = _text(row.get(rule["detail"])) if rule.get("detail") else ""
    if rule.get("detail") is None:
        rest = {k: v for k, v in row.items() if k != rule["timestamp"] and v not in (None, "")}
        if rest:
            detail = json.dumps(rest, ensure_ascii=False, sort_keys=True, default=str)
    extra = {column: row[column] for column in rule.get("extra") or [] if column in row and row[column] not in (None, "")}
    return {"record_id": index, "timestamp": date, "action": action, "detail": detail, "extra": extra}


def _rule_note(rule: dict[str, Any], columns: list[str]) -> dict[str, Any]:
    note: dict[str, Any] = {
        key: rule[key]
        for key in ("timestamp", "action", "detail", "extra", "table", "timestamp_format", "strategy")
        if key in rule and rule[key] is not None
    }
    note["columns"] = list(columns)
    return note


# -------------------------------------------------------------- text formats


def _open_text(path: Path, stream: TextIO | None) -> tuple[TextIO, bool]:
    if stream is not None:
        return stream, False
    return path.open(encoding="utf-8", errors="replace"), True


def parse_csv(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult:
    source, close = _open_text(path, stream)
    try:
        reader = csv.DictReader(source)
        columns = list(reader.fieldnames or [])
        rows = [row for row in reader]
        if not columns and not rows:
            return [], {"columns": [], "strategy": "empty"}
        rule = pick_mapping(relative, mapping) or _auto_mapping(columns, rows[:20])
        if rule is None:
            raise ValueError(f"No timestamp column identified: {relative}")
        records = [_record_from_rule(row, rule, relative, index) for index, row in enumerate(rows, 1)]
        return records, _rule_note(rule, columns)
    finally:
        if close:
            source.close()


def parse_jsonl(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult:
    source, close = _open_text(path, stream)
    try:
        rows: list[dict[str, Any]] = []
        sample: list[dict[str, Any]] = []
        for index, line in enumerate((chunk for chunk in source if chunk.strip()), 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Unreadable JSON line: {relative}, record {index}") from error
            if not isinstance(row, dict):
                raise ValueError(f"JSON record is not an object: {relative}, record {index}")
            rows.append(row)
            if len(sample) < 20:
                sample.append(row)
        if not rows:
            return [], {"columns": [], "strategy": "auto-detected"}
        keys: list[str] = []
        for row in sample:
            for key in row:
                if key not in keys:
                    keys.append(key)
        rule = pick_mapping(relative, mapping) or _auto_mapping(keys, sample)
        if rule is None:
            raise ValueError(f"No timestamp field identified: {relative}")
        records = [_record_from_rule(row, rule, relative, index) for index, row in enumerate(rows, 1)]
        return records, _rule_note(rule, keys)
    finally:
        if close:
            source.close()


def parse_text_log(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult:
    """Syslog (simplified RFC 5424, or RFC 3164 with declared assumptions) or Apache combined."""
    source, close = _open_text(path, stream)
    try:
        lines = [(index, line.rstrip("\n")) for index, line in enumerate(source, 1) if line.strip()]
        if not lines:
            return [], {"format": "empty"}
        apache_mode = bool(APACHE.match(lines[0][1]))
        records = [
            (parse_apache_line(line, relative, index) if apache_mode else parse_syslog_line(line, relative, index, assumptions or {}))
            for index, line in lines
        ]
        return records, {"format": "apache-combined" if apache_mode else "syslog"}
    finally:
        if close:
            source.close()


def parse_syslog_line(line: str, relative: str, index: int, assumptions: dict[str, Any]) -> Record:
    text = SYSLOG_PREFIX.sub("", line.strip())
    tokens = text.split(None, 3)
    if len(tokens) >= 4:
        stamp, host, app, message = tokens
        date: datetime | None
        try:
            date = parse_iso(stamp, relative, index)
        except ValueError:
            date = None
        if date is not None:
            app = re.sub(r"\[\d+\]$", "", app.rstrip(":"))
            return {"record_id": index, "timestamp": date, "action": app or "syslog", "detail": message, "extra": {"host": host}}
    match = RFC3164.match(text)
    if match is None:
        raise ValueError(f"Unparsed log line: {relative}, record {index}")
    tz, year = assumptions.get("tz"), assumptions.get("year")
    if tz is None or year is None:
        raise ValueError(f"Syslog timestamp needs --assume-offset and --assume-year: {relative}, record {index}")
    month, day, clock, host, app, _pid, message = match.groups()
    hour, minute, second = (int(part) for part in clock.split(":"))
    return {
        "record_id": index,
        "timestamp": datetime(int(year), MONTHS[month], int(day), hour, minute, second, tzinfo=tz),
        "action": app,
        "detail": message,
        "extra": {"host": host},
    }


def parse_apache_line(line: str, relative: str, index: int) -> Record:
    match = APACHE.match(line.rstrip("\n"))
    if match is None:
        raise ValueError(f"Unparsed log line: {relative}, record {index}")
    client, _ident, user, stamp, request, status, size, referer, agent = match.groups()
    time_match = APACHE_TIME.match(stamp)
    if time_match is None:
        raise ValueError(f"Unreadable timestamp: {relative}, record {index} ({stamp!r})")
    day, month, year, hour, minute, second, sign, off_h, off_m = time_match.groups()
    if month not in MONTHS:
        raise ValueError(f"Unreadable timestamp: {relative}, record {index} ({stamp!r})")
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    date = datetime(
        int(year), MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=timezone(offset if sign == "+" else -offset)
    )
    method, _space, target = (request.split(maxsplit=2) + ["", "", ""])[:3] if request.strip() else ("", "", "")
    extra = {"client_ip": client, "user": user, "status": status, "bytes": size, "referrer": referer or "", "user_agent": agent or ""}
    return {
        "record_id": index,
        "timestamp": date,
        "action": method or "request",
        "detail": f"{request} {status} {size}".strip(),
        "extra": extra,
    }


# ------------------------------------------------------------ mbox / sqlite


def parse_mbox(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult:
    import mailbox

    box = mailbox.mbox(str(path), create=False)
    try:
        messages = list(box)
    finally:
        box.close()
    records: list[Record] = []
    for index, message in enumerate(messages, 1):
        raw = message.get("Date")
        if raw is None:
            raise ValueError(f"Missing timestamp: {relative}, record {index}")
        try:
            date = parsedate_to_datetime(str(raw))
        except (TypeError, ValueError, IndexError) as error:
            raise ValueError(f"Unreadable timestamp: {relative}, record {index}") from error
        if date is None or date.tzinfo is None:
            raise ValueError(f"Timestamp has no timezone: {relative}, record {index}")
        records.append(
            {
                "record_id": index,
                "timestamp": date,
                "action": "email",
                "detail": _text(message.get("Subject")) or "(no subject)",
                "extra": {
                    "from": _text(message.get("From")),
                    "to": _text(message.get("To")),
                    "message_id": _text(message.get("Message-ID")),
                },
            }
        )
    return records, {"format": "mbox", "messages": len(records)}


def _quoted(identifier: str) -> str:
    if '"' in identifier or "\x00" in identifier:
        raise ValueError(f"Unsupported SQLite identifier: {identifier!r}")
    return f'"{identifier}"'


def parse_sqlite(
    path: Path, relative: str, *, mapping: dict[str, Any] | None = None, assumptions: dict[str, Any] | None = None
) -> ParseResult:
    rule = pick_mapping(relative, mapping) or {}
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        tables = [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        ]
        if rule.get("table"):
            tables = [table for table in tables if table == rule["table"]]
            if not tables:
                raise ValueError(f"Mapped table not found: {relative}")
        records: list[Record] = []
        notes: list[dict[str, Any]] = []
        for table in tables:
            found = _parse_sqlite_table(connection, table, rule, relative)
            if found is None:
                notes.append({"table": table, "status": "no timestamp column identified"})
            else:
                table_records, columns, used = found
                multi = len(tables) > 1
                for record in table_records:
                    if multi:
                        record["record_id"] = f"{table}#{record['record_id']}"
                records.extend(table_records)
                notes.append({"table": table, "records": len(table_records), "mapping": _rule_note(used, columns)})
        return records, {"tables": notes}
    finally:
        connection.close()


def _parse_sqlite_table(
    connection: sqlite3.Connection, table: str, rule: dict[str, Any], relative: str
) -> tuple[list[Record], list[str], dict[str, Any]] | None:
    columns = [row[1] for row in connection.execute(f"PRAGMA table_info({_quoted(table)})")]
    if not columns:
        return None
    lower = {column.strip().lower(): column for column in columns}
    timestamp = rule.get("timestamp")
    if timestamp and timestamp not in columns:
        raise ValueError(f"Mapped timestamp column missing: {relative}, table {table}")
    if timestamp is None:
        timestamp = next((lower[key] for key in TIMESTAMP_KEYS if key in lower), None)
    if timestamp is None:
        for column in columns:
            try:
                sample = [row[0] for row in connection.execute(f"SELECT {_quoted(column)} FROM {_quoted(table)} LIMIT 20")]
            except sqlite3.Error:
                continue
            if sample and sum(1 for value in sample if _looks_aware(value)) / len(sample) >= 0.6:
                timestamp = column
                break
    if timestamp is None:
        return None
    action = rule.get("action") if rule.get("action") in columns else None
    if action is None:
        action = next((lower[key] for key in ACTION_KEYS if key in lower and lower[key] != timestamp), None)
    detail = rule.get("detail") if rule.get("detail") in columns else None
    if detail is None:
        detail = next((lower[key] for key in DETAIL_KEYS if key in lower and lower[key] not in (timestamp, action)), None)
    extra_columns = [column for column in columns if column not in (timestamp, action, detail)]
    used = {
        "timestamp": timestamp,
        "action": action,
        "detail": detail,
        "extra": extra_columns,
        "strategy": "mapping file" if rule else "auto-detected",
    }
    try:
        cursor = connection.execute(f"SELECT rowid AS __rowid__, * FROM {_quoted(table)} ORDER BY rowid")
        description = cursor.description
        assert description is not None
        names = [row[0] for row in description][1:]
        rows = [dict(zip(names, row[1:], strict=True)) | {"__rowid__": row[0]} for row in cursor]
    except sqlite3.Error:
        cursor = connection.execute(f"SELECT * FROM {_quoted(table)}")
        description = cursor.description
        assert description is not None
        names = [row[0] for row in description]
        rows = [dict(zip(names, row, strict=True)) for row in cursor]
    records: list[Record] = []
    for index, row in enumerate(rows, 1):
        record_action = _text(row.get(action)) if action else "record"
        if detail:
            record_detail = _text(row.get(detail))
        else:
            rest = {k: v for k, v in row.items() if k != timestamp and k != "__rowid__" and v not in (None, "")}
            record_detail = json.dumps(rest, ensure_ascii=False, sort_keys=True, default=str) if rest else ""
        extra = {column: row.get(column) for column in extra_columns if row.get(column) not in (None, "")}
        records.append(
            {
                "record_id": row.get("__rowid__", index),
                "timestamp": parse_timestamp(row.get(timestamp), relative, index, rule.get("timestamp_format")),
                "action": record_action or "record",
                "detail": record_detail,
                "extra": extra,
            }
        )
    return records, columns, used


# ------------------------------------------------------------- archives etc.


def parse_gzip(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult | None:
    inner_name = relative[:-3]
    inner = resolve_parser(inner_name)
    if inner is None or inner not in (parse_csv, parse_jsonl, parse_text_log):
        return None
    if stream is not None:
        binary = gzip.GzipFile(fileobj=stream.buffer)
    else:
        binary = gzip.open(str(path), "rb")
    with binary:
        text = io.TextIOWrapper(binary, encoding="utf-8", errors="replace")
        found = inner(path, inner_name, mapping=mapping, assumptions=assumptions, stream=text)
    if found is None:
        return None
    records, notes = found
    notes["container"] = "gzip"
    return records, notes


def parse_zip(
    path: Path,
    relative: str,
    *,
    mapping: dict[str, Any] | None = None,
    assumptions: dict[str, Any] | None = None,
    stream: TextIO | None = None,
) -> ParseResult:
    records: list[Record] = []
    members: list[dict[str, Any]] = []
    with zipfile.ZipFile(str(path)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise ValueError(f"Encrypted zip member is unsupported: {relative}!{info.filename}")
            inner = resolve_parser(info.filename)
            if inner is None:
                members.append({"member": info.filename, "status": "unsupported"})
                continue
            with archive.open(info) as raw:
                text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                found = inner(path, info.filename, mapping=mapping, assumptions=assumptions, stream=text)
            if found is None:
                members.append({"member": info.filename, "status": "unsupported"})
                continue
            member_records, notes = found
            for record in member_records:
                record["extra"] = {**(record.get("extra") or {}), "member": info.filename}
                record["record_id"] = f"{info.filename}#{record['record_id']}"
            records.extend(member_records)
            members.append(
                {
                    "member": info.filename,
                    "records": len(member_records),
                    "format": notes.get("format") or notes.get("strategy") or "parsed",
                }
            )
    return records, {"container": "zip", "members": members}


SUFFIX_PARSERS: dict[str, ParserFn] = {
    ".csv": parse_csv,
    ".jsonl": parse_jsonl,
    ".ndjson": parse_jsonl,
    ".sqlite": parse_sqlite,
    ".sqlite3": parse_sqlite,
    ".db": parse_sqlite,
    ".mbox": parse_mbox,
    ".log": parse_text_log,
    ".syslog": parse_text_log,
}


def resolve_parser(name: str) -> ParserFn | None:
    lower = name.lower()
    if lower.endswith(".gz"):
        return parse_gzip
    if lower.endswith(".zip"):
        return parse_zip
    for suffix, parser in SUFFIX_PARSERS.items():
        if lower.endswith(suffix):
            return parser
    return None


def parse_evidence(
    path: Path, relative: str, *, mapping: dict[str, Any] | None = None, assumptions: dict[str, Any] | None = None
) -> ParseResult | None:
    """Returns (records, notes) or None when the format is unsupported."""
    parser = resolve_parser(relative)
    if parser is None:
        return None
    found = parser(path, relative, mapping=mapping, assumptions=assumptions)
    if found is None:
        return None
    records, notes = found
    for record in records:
        record.setdefault("extra", {})
    return records, notes
