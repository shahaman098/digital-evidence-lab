# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
semver-flavoured while the project remains pre-1.0. This is an educational
project: nothing here is certified forensic software.

## [0.3.0] — 2026-11-01

### Added
- `evidence-lab demo` one-command walkthrough: generates the fictional scenario,
  collects, verifies, analyses and opens the HTML report (`--no-open` to skip
  the browser). The generator moved into the package (`evidence_lab.demo`);
  the root `make_demo.py` remains as a compatibility shim.
- Hand-rolled terminal polish with zero dependencies: ANSI progress bars and
  status colours (`evidence_lab.ui`), auto-enabled on TTYs, honouring
  `NO_COLOR`/`TERM=dumb`, with `--progress`, `--no-progress` and `--no-color`
  overrides.
- Type hints across the package; `mypy` and `ruff` gates; coverage measurement.
- `search` accepts the same `--mapping` file as `timeline`, so cases with
  exotic source columns behave identically in both commands.

### Changed
- Progress callbacks now receive `(done, total, message)` instead of a message.
- The version is single-sourced from `evidence_lab.core.VERSION` via the
  package metadata.

## [0.2.0] — 2026-10-31

### Added
- Parser registry: mbox, RFC 5424/3164 syslog, Apache combined logs, gzip and
  zip members, and multi-table SQLite discovery, on top of CSV/JSONL.
- Configurable field mapping (`--mapping`) with exact/glob rules and recorded
  auto-detection; hash-set sidecar classification (`--hashset`).
- Analysis layer: keyword search (literal/regex), entity extraction, session
  gap detection, per-hour histogram; `search` subcommand.
- `report.json` v2 with `field_mappings`, `timestamp_assumptions`,
  `file_classifications` and analysis sections; self-contained `report.html`
  with inline SVG charts.
- Parallel hashing/copying via `--jobs`; `--verbose`; packaging
  (`pyproject.toml`, `evidence-lab` console script); CI on Python 3.11–3.14.

### Changed
- Restructured the flat `evidence_lab.py` script into the `evidence_lab`
  package. Case formats (`digital-evidence-lab.case.v1`) are unchanged.

## [0.1.0] — 2026-10-29

### Added
- Initial lab: logical collection with SHA-256 manifest, hash-linked handling
  log and anchors, integrity verification, UTC timeline extraction from
  CSV/JSONL/SQLite with provenance, and the synthetic demo scenario.
