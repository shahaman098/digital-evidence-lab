# Method and review worksheet

This AI-assisted educational exercise explores **forensic principles and technologies** through copied-file integrity, explicit handling records and source-linked reporting. Its **forensic practices and protocols** are the narrow lab procedure below, not an accredited operating procedure. Running this code does not establish independent investigator competence.

## 1. Identify the source and scope

Use `make_demo.py` — or the `demo` subcommand, which runs this whole worksheet flow (sections 2–5) on a fresh fictional directory — to create a closed, fictional scenario. Record the source's purpose and operator before collection. The files represent already-exported application records: a cloud-audit CSV, a mobile-message JSONL export, an mbox mailbox, syslog and Apache-style logs, a zip archive of CSV exports and a two-table SQLite database. They are not phone extractions, disk images, mail-server captures or live cloud records.

In a real investigation, authority to collect, evidence sensitivity, device state, volatility and legal/process requirements would need decisions outside this tool. This project makes none of those decisions and is not suitable as a replacement for validated acquisition software.

## 2. Collect logical copies

Choose a new case ID and a destination separate from the source. `collect` lists regular files, rejects symbolic links and creates a new case rather than overwriting one. For each file, it records size and observed modification time, copies bytes while hashing them, checks that the opened source's identity/size/times did not change during that copy, and independently rehashes the destination. With `--jobs N` the copies and hashes run in parallel while the handling log keeps its deterministic sorted order; the per-file checks are unchanged.

These checks detect several consistency failures. They do not freeze the entire directory or stop a hostile process changing sources between file copies. Reading may update source access times. There is no write blocker or atomic filesystem snapshot.

## 3. Document handling

The manifest identifies each copied file by relative path, byte count and SHA-256. The handling log records the supplied operator label, UTC observation time, copy verification and collection completion. Each event references its predecessor's hash. This is a software activity log, not proof of a human custodian's identity.

Store the two returned anchor hashes outside the case if you want to detect a replacement of the case and its local anchors. The tool has no signing key, trusted timestamp service or immutable storage. A self-consistent rewritten log remains possible when verification trusts only that same directory.

## 4. Examine copies and retain provenance

`timeline` (and `search`) verify the case first. Parsing is suffix-driven, with gzip and zip containers unwrapped to their inner names and SQLite opened read-only over every user table. Field mapping to `timestamp`/`action`/`detail` is either automatic (name candidates plus value sniffing) or supplied through a mapping file; whichever rule was actually applied is copied into the report's `field_mappings`, so a reader can audit how each column was interpreted. Every extracted record retains its source filename, source record identity (`table#rowid` for SQLite, `member#record` for zip archives) and source-file hash. Unsupported files are listed, never silently analysed.

Timestamps must include an offset, or the run fails. The single exception is RFC 3164 syslog lines, whose format cannot express a zone: they are parsed only under explicitly declared `--assume-offset`/`--assume-year` values, and the report discloses those assumptions under `timestamp_assumptions`. The lab normalises everything to UTC for ordering without asserting that the source clocks were accurate.

## 5. Analysis is triage, not conclusion

The keyword, entity and session features are text triage over already-verified copies:

- **Keyword hits** mean a literal (or regex) string occurs in an action, detail or extra field. They do not show intent, significance or who typed it. Regex terms that are too broad (for example a bare `.`) match everything and say nothing.
- **Entities** come from regular expressions. IP-looking strings may be versions or prose; domains may be filenames; the same value can appear under several kinds. Extraction is a pointer into the records, not an identification of an actor or system.
- **Sessions** split wherever the chosen gap threshold is exceeded. The threshold is arbitrary, and a quiet period is not evidence that nothing happened.
- **Histograms and counts** summarise untrusted source clocks. They describe the records, not the world.
- **Hash-set labels** say only that a digest appeared in a sidecar the operator supplied. They carry no external authority.

None of these outputs is a conclusion. They exist to point a human reviewer at records worth reading, with the provenance needed to check them.

## 6. Report observations separately from conclusions

The actual demonstration yields twelve synthetic records between 08:31 and 11:47 UTC on 1 October 2026, including:

- device-agent syncs at 08:31 and 08:32 UTC (RFC 5424 log);
- cloud login at 09:01 UTC;
- an exported message at 09:02 UTC after converting its +01:00 offset;
- cloud download at 09:03 UTC;
- SQLite events at 09:04 and 09:06 UTC from two tables;
- archived visit records at 09:08 and 11:45 UTC;
- an email at 09:10 UTC;
- Apache-style GETs at 11:46 and 11:47 UTC.

A 2h35m silence separates the morning cluster from the late-morning one; with `--session-gap 1800` the report shows two sessions. That gap is a property of the fictional data, not an inference about behaviour.

The warranted conclusion is that these synthetic records contain those values. The output cannot establish a real incident or prove the message caused the download. A review should preserve these uncertainties instead of presenting a definitive story.

Before accepting a report, compare its rows to the source records, verify with independently retained anchors, inspect the `field_mappings`, `timestamp_assumptions` and unsupported-file notices, and read the timestamp and scope warnings. Run the tests to see failures for changes, missing files, extra files, truncated logs, interrupted collection, and the parser and analysis edge cases.

## Reference and limits

[NIST SP 800-86](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf), especially section 3.2 and Appendix A, informs this project's distinction between collection, examination, analysis and reporting, and the need to document actions and check copy integrity. This worksheet is original explanatory prose tied to the code; it is not a certification, a finding of standards compliance or legal advice.
