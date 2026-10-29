# Digital Evidence Lab

A small Python lab for collecting **logical file copies**, checking their integrity and building a timeline from exported records. Created on **29 October 2026**, with AI coding assistance, as a new portfolio exercise. It demonstrates the software below; it does not establish earlier forensic employment, independent specialist-tool proficiency or a completed forensic course.

The included scenario is fictional. It combines a cloud-audit CSV, a mobile-message JSONL export and a small SQLite event database. The generator creates every byte locally; it does not read a browser profile, phone, account or private dataset.

## Run it

Python 3.11+ on macOS or Linux; no third-party packages or API keys.

```sh
python3 -m unittest discover -s tests -v
python3 make_demo.py demo-source
python3 evidence_lab.py collect demo-source demo-case --operator "Training operator" --case-id SYNTHETIC-001
python3 evidence_lab.py verify demo-case
python3 evidence_lab.py timeline demo-case demo-analysis
```

The timeline has four records, normalised to UTC: cloud login, exported message, cloud download and browser-export event. Each record retains its source filename, record number and SHA-256 digest. The JSON preserves source text; the CSV neutralises leading spreadsheet-formula characters.

Files produced:

```text
demo-case/
  evidence/          # copies, never analysis output
  manifest.json      # file digests, sizes and observed source modification times
  handling.jsonl     # ordered, hash-linked collection events with operator/time
  anchor.json        # manifest and final handling-log hashes
demo-analysis/
  timeline.json
  timeline.csv
  report.json        # scope, unsupported files and timestamp limitations
```

`collect` never overwrites an existing case. It refuses overlapping paths, symbolic links and non-regular inputs, compares source metadata before/after copying, independently rehashes each destination and marks caught failures or keyboard interruptions incomplete. Abrupt termination such as SIGKILL cannot write that marker; missing completion metadata still prevents verification. Reading can update filesystem access times: this is **not write-blocked acquisition** and does not preserve every filesystem attribute.

`verify` rejects changed, missing or additional evidence, altered or truncated handling logs, duplicate paths and mismatches between copy events and the manifest. `timeline` verifies before and after extraction, opens SQLite in read-only immutable mode, requires timezone-aware timestamps and writes outside the case. Unknown file formats are explicitly listed, not silently analysed.

## What the hashes do—and do not—prove

The handling log is hash-linked, not signed, externally timestamped or protected against privileged rewriting. A person who can replace the entire case can recompute all local hashes. Retain the two hashes returned by `collect` in an independent trusted location, then provide them during verification:

```sh
python3 evidence_lab.py verify demo-case \
  --expected-manifest MANIFEST_SHA256 \
  --expected-handling HANDLING_SHA256
```

Those command arguments must be the actual returned values, not the illustrative names above. Local hash agreement checks internal consistency. It does not prove the original source was truthful, identify a human custodian or establish legal admissibility. A sorted timeline is not proof of causation, and source clocks may be wrong.

## Design reference

[NIST SP 800-86, section 3.2 and Appendix A](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf) discusses preserving copied data, checking integrity and documenting collection actions. This exercise applies those ideas to a narrow logical-file workflow. It is **not certified, standards-compliant forensic acquisition** or a substitute for an organisation's forensic practices and protocols.

## Scope and evidence boundaries

- Implemented: Python file copying, SHA-256 checks, handling-event hash chains, CSV/JSONL/SQLite extraction, UTC timeline analysis and provenance reporting.
- Demonstrated on synthetic exports representing mobile devices, cloud activity and personal computer systems; **no actual device acquisition** or live cloud collection is implemented.
- No physical disk imaging, deleted-file recovery, filesystem carving, device unlocking, professional chain-of-custody system or independent tool validation.
- No EnCase, Cellebrite, X-Ways, MS Access or Visual Basic integration. These names describe exclusions, not experience or skills.
- Use only the supplied synthetic fixtures or data you own and are authorised to examine. This educational parser is not hardened to process hostile evidence or large volumes; collection is not an atomic filesystem snapshot. Stable source directories and a trusted local operator are assumed.

See [the tests](tests/test_evidence_lab.py) for tampering, truncation, path/symlink, timestamp, source-preservation and cross-source timeline checks. [The example report](examples/report.json) and [timeline](examples/timeline.csv) are actual outputs from the supplied synthetic scenario.

The [method and review worksheet](docs/method-and-review.md) explains the lab procedure, provenance checks and limits on conclusions.

## Attribution

Requested by Aman Kumar Sah and implemented with Codex assistance on 29 October 2026. Test and demonstration execution were performed by the coding agent. The repository is dated new work; it makes no claim that the owner independently wrote every line or operated commercial forensic tools.

MIT licensed; see [LICENSE](LICENSE).
