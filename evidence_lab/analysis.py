"""Read-only analysis over verified timeline rows.

Everything here is heuristic triage over text: keyword hits are not evidence of
significance, entity extraction is regex-based, and session boundaries are an
arbitrary gap threshold — none of it establishes causation or intent.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

Row = dict[str, Any]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
ENTITY_KINDS = (("url", URL_RE), ("email", EMAIL_RE), ("ipv4", IPV4_RE), ("sha256", HEX64_RE), ("domain", DOMAIN_RE))


def row_text(row: Row) -> str:
    parts = [row.get("action") or "", row.get("detail") or ""]
    parts.extend(str(value) for value in (row.get("extra") or {}).values())
    return " \n ".join(part for part in parts if part)


def row_fields(row: Row) -> dict[str, str]:
    fields = {"action": row.get("action") or "", "detail": row.get("detail") or ""}
    for key, value in (row.get("extra") or {}).items():
        fields[f"extra.{key}"] = str(value)
    return fields


def _matcher(term: str, regex: bool = False) -> re.Pattern[str]:
    return re.compile(term if regex else re.escape(term), re.IGNORECASE)


def keyword_results(rows: list[Row], terms: list[str], regex: bool = False, cap: int = 100) -> list[dict[str, Any]]:
    """Per-term hit counts plus capped, provenance-carrying matches."""
    results: list[dict[str, Any]] = []
    for term in terms:
        matcher = _matcher(term, regex)
        count = 0
        matches: list[dict[str, Any]] = []
        for row in rows:
            for field, text in row_fields(row).items():
                hits = list(matcher.finditer(text))
                if not hits:
                    continue
                count += len(hits)
                if len(matches) < cap:
                    first = hits[0]
                    start, end = max(0, first.start() - 60), min(len(text), first.end() + 60)
                    excerpt = ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")
                    matches.append(
                        {
                            "timestamp": row["timestamp"],
                            "source": row["source"],
                            "source_record": row["source_record"],
                            "field": field,
                            "excerpt": excerpt,
                        }
                    )
        results.append({"term": term, "regex": regex, "count": count, "matches": matches, "matches_truncated": count > len(matches)})
    return results


def search_rows(rows: list[Row], query: str, regex: bool = False, cap: int = 200) -> dict[str, Any]:
    return keyword_results(rows, [query], regex=regex, cap=cap)[0]


def _valid_ipv4(value: str) -> bool:
    return all(0 <= int(part) <= 255 for part in value.split("."))


def entities(rows: list[Row], cap_examples: int = 3) -> dict[str, list[dict[str, Any]]]:
    """Unique regex-extracted entities with counts, first/last sighting and examples."""
    found: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        text = row_text(row)
        for kind, expression in ENTITY_KINDS:
            for match in expression.finditer(text):
                value = match.group(0).rstrip(".,;")
                if kind == "ipv4" and not _valid_ipv4(value):
                    continue
                key = value.lower() if kind in ("email", "domain") else value
                entry = found.setdefault(kind, {}).setdefault(
                    key, {"value": value, "count": 0, "first_seen": row["timestamp"], "last_seen": row["timestamp"], "examples": []}
                )
                entry["count"] += 1
                entry["first_seen"] = min(entry["first_seen"], row["timestamp"])
                entry["last_seen"] = max(entry["last_seen"], row["timestamp"])
                if len(entry["examples"]) < cap_examples:
                    entry["examples"].append({"source": row["source"], "source_record": row["source_record"]})
    return {kind: sorted(values.values(), key=lambda e: (-e["count"], e["value"])) for kind, values in found.items() if values}


def sessions(rows: list[Row], gap_seconds: int) -> dict[str, Any]:
    """Group chronologically sorted rows into sessions split at silent gaps."""
    result: dict[str, Any] = {"gap_seconds": gap_seconds, "count": 0, "sessions": [], "largest_gaps": []}
    if not rows or not gap_seconds or gap_seconds < 1:
        return result
    times = [datetime.fromisoformat(row["timestamp"]) for row in rows]
    starts = [0] + [index for index in range(1, len(rows)) if (times[index] - times[index - 1]).total_seconds() > gap_seconds]
    bounds = starts + [len(rows)]
    groups = [rows[begin:end] for begin, end in zip(starts, bounds[1:], strict=False)]
    gaps = sorted(((times[index] - times[index - 1]).total_seconds(), index) for index in range(1, len(rows)))
    result["count"] = len(groups)
    result["sessions"] = [{"start": group[0]["timestamp"], "end": group[-1]["timestamp"], "records": len(group)} for group in groups]
    result["largest_gaps"] = [
        {"after": rows[index - 1]["timestamp"], "before": rows[index]["timestamp"], "seconds": round(seconds, 3)}
        for seconds, index in reversed(gaps[-5:])
    ]
    return result


def histogram(rows: list[Row], cap: int = 2000) -> list[dict[str, Any]]:
    """Contiguous per-hour UTC record counts across the observed span."""
    counts: Counter[datetime] = Counter()
    for row in rows:
        stamp = datetime.fromisoformat(row["timestamp"]).replace(minute=0, second=0, microsecond=0)
        counts[stamp] += 1
    if not counts:
        return []
    current = min(counts)
    out: list[dict[str, Any]] = []
    while current <= max(counts) and len(out) < cap:
        out.append({"hour": current.isoformat(), "records": counts.get(current, 0)})
        current += timedelta(hours=1)
    return out


def summarize(rows: list[Row]) -> dict[str, Any]:
    per_source = Counter(row["source"] for row in rows)
    per_action = Counter(row["action"] for row in rows)
    return {
        "records": len(rows),
        "files": len(per_source),
        "first": rows[0]["timestamp"] if rows else None,
        "last": rows[-1]["timestamp"] if rows else None,
        "per_source": dict(sorted(per_source.items())),
        "per_action": dict(sorted(per_action.items())),
    }
