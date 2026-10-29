# Method and review worksheet

This AI-assisted educational exercise explores **forensic principles and technologies** through copied-file integrity, explicit handling records and source-linked reporting. Its **forensic practices and protocols** are the narrow lab procedure below, not an accredited operating procedure. Running this code does not establish independent investigator competence.

## 1. Identify the source and scope

Use `make_demo.py` to create a closed, fictional scenario. Record the source's purpose and operator before collection. The four files represent already-exported application records. They are not phone extractions, disk images or live cloud records.

In a real investigation, authority to collect, evidence sensitivity, device state, volatility and legal/process requirements would need decisions outside this tool. This project makes none of those decisions and is not suitable as a replacement for validated acquisition software.

## 2. Collect logical copies

Choose a new case ID and a destination separate from the source. `collect` lists regular files, rejects symbolic links and creates a new case rather than overwriting one. For each file, it records size and observed modification time, copies bytes while hashing them, checks that the opened source's identity/size/times did not change during that copy, and independently rehashes the destination.

These checks detect several consistency failures. They do not freeze the entire directory or stop a hostile process changing sources between file copies. Reading may update source access times. There is no write blocker or atomic filesystem snapshot.

## 3. Document handling

The manifest identifies each copied file by relative path, byte count and SHA-256. The handling log records the supplied operator label, UTC observation time, copy verification and collection completion. Each event references its predecessor's hash. This is a software activity log, not proof of a human custodian's identity.

Store the two returned anchor hashes outside the case if you want to detect a replacement of the case and its local anchors. The tool has no signing key, trusted timestamp service or immutable storage. A self-consistent rewritten log remains possible when verification trusts only that same directory.

## 4. Examine copies and retain provenance

`timeline` first verifies the case. It parses only known CSV/JSONL fields and a SQLite `events` table; the database connection is read-only. It does not inspect arbitrary browsers or execute evidence as programs. Every extracted record retains its source filename, ordinal position and source-file hash. Unsupported files appear in the report.

Timestamps must include an offset. The lab normalises them to UTC for ordering without asserting that the source clocks were accurate. All four fictional events can be placed in an order, but that does not prove a causal relationship, an identity or malicious intent.

## 5. Report observations separately from conclusions

The actual demonstration yields:

- cloud login at 09:01 UTC;
- an exported message at 09:02 UTC after converting its +01:00 offset;
- cloud download at 09:03 UTC;
- a browser-export event at 09:04 UTC.

The warranted conclusion is that these synthetic records contain those values. The output cannot establish a real incident or prove the message caused the download. A review should preserve these uncertainties instead of presenting a definitive story.

Before accepting a report, compare its rows to the source records, verify with independently retained anchors, inspect unsupported-file notices, and read the timestamp and scope warnings. Run the tests to see failures for changes, missing files, extra files, truncated logs and interrupted collection.

## Reference and limits

[NIST SP 800-86](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf), especially section 3.2 and Appendix A, informs this project's distinction between collection, examination, analysis and reporting, and the need to document actions and check copy integrity. This worksheet is original explanatory prose tied to the code; it is not a certification, a finding of standards compliance or legal advice.
