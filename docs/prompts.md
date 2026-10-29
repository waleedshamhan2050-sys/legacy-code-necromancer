# Prompts used by the Legacy Code Necromancer

The exact prompt texts live in `necromancer.py`
(`AUTOPSY_*`, `REFACTOR_*`, `REPORT_*`). This file records the intent
of each pass so a run can be reproduced or reviewed without reading
code.

## Autopsy pass (temperature 0.2)

Role: senior code pathologist. The model receives one file per call,
split into contiguous line ranges of at most 6,000 characters. It
returns a short prose verdict plus a fenced ```json block: an array of
findings with exactly these fields — `severity` (Critical/High/Medium/
Low), `category` (security, deprecated-api, correctness, reliability,
maintainability), `title`, `line`, `evidence` (max 3 lines),
`explanation`, `fix`. Empty arrays are valid; findings must not be
invented. Credentials are never repeated — the model writes
`SECRET-REDACTED`, and the tool redacts them before prompting anyway.

## Refactor pass (temperature 0.2)

Role: senior engineer. The model receives the whole file (only if it
fits in one pass — under 9,000 characters) plus the autopsy findings,
and must return **only** a fenced code block with the complete
modernised file: same behaviour and messages, secrets from the
environment with fail-fast validation, UTC datetimes, no blocking I/O
in async code, backoff on rate limits, type hints and docstrings, no
new dependencies.

## Report pass (temperature 0.2)

Role: technical writer. From the findings summary and the revival
summary, the model writes the "Cause of Death" and "Resurrection
Notes" sections of the haunted audit report, ending with a "Before
you deploy" checklist (secrets rotation, environment variables, data
migration). The surrounding report — vitals, tables, verification,
séance log — is rendered deterministically by the tool, never by the
model.

## Safety rules applied before any prompt is sent

1. `redact_secrets()` strips credential-looking lines, known
   credential prefixes, and PEM blocks. The model never sees a
   secret, even locally.
2. The Ollama endpoint must be loopback (`127.0.0.1`/`localhost`)
   unless `--allow-remote` is passed explicitly.
3. Raw model output is preserved verbatim under `seance/` — nothing
   is silently edited before the human curator reads it.
4. Files over the rewrite size cap are autopsied only, never
   rewritten chunk-by-chunk.
