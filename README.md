# 👻 The Legacy Code Necromancer

> **Hacktoberfest 2026 — "Ghost in the Machine" challenge entry, Best Use of Gemma category.**
> A local-first CLI that dissects abandoned code, resurrects it with
> **Gemma 3 running entirely on your own machine through Ollama**, and
> writes a haunted audit report you can verify line by line.
> No cloud. No API keys. No code ever leaves localhost.

Every codebase has a graveyard: the utility written in 2019 that
everyone is afraid to touch, the intern's bot, the script with the
password still in it. The Necromancer does not delete the dead — it
performs an autopsy, determines the cause of death, and brings the
code back in a form that is safe to run. The ghost in the machine is
not something to fear. It is something to understand.

## The pipeline — three engines, one séance

```
abandoned project ──► 1. CODE AUTOPSY ──► 2. AUTO-REFACTORING ──► 3. HAUNTED AUDIT REPORT
                        (Gemma 3, local)    (Gemma 3, local)        (Markdown, verifiable)
```

| Engine | What it does | Output |
|---|---|---|
| **1. Code Autopsy** | Examines every source file for security vulnerabilities, deprecated/removed APIs, and structural defects. Findings are structured data: severity, category, file, line, evidence, fix. | `seance/*.autopsy.md` (raw replies) + findings in the report |
| **2. Auto-Refactoring & Patching** | Gemma drafts a modern, clean, safe version of each file that fits in one model pass, preserving behaviour. Python drafts must compile or they are marked unverified. | `revived/` (mirrors the input tree) |
| **3. Haunted Audit Report** | A Markdown report with the Halloween spirit of the challenge on its sleeve and engineering precision underneath: vitals, cause of death, wounds, resurrections, verification, and the full séance log. | `haunted-audit-report.md` |

## Why local-first is the whole point

The challenge asks what open innovation makes possible. Here is the
concrete answer: **running your own model means the autopsy never
depends on a service that can disappear, change its prices, or read
your code.** Abandoned code is often the most sensitive code a person
owns — half-finished, half-secret, full of old credentials. Uploading
it to a cloud reviewer is exactly what you should not do. With Gemma 3
on localhost:

- **Privacy by architecture.** Loopback-only by default; a remote
  Ollama host is refused unless `--allow-remote` is passed
  explicitly. No telemetry, no keys, no accounts.
- **Secrets are filtered before prompting.** The tool redacts
  hardcoded credentials, tokens, private keys, and high-entropy
  literals before the model ever sees the code — the model never
  receives a secret, even locally. Redactions are counted and
  reported.
- **Reproducibility.** Prompts, raw model output, timings, and a
  run manifest are all preserved. Anyone can rerun the identical
  séance offline and audit every finding against the reply that
  produced it.
- **It works with the lights off.** For a student on a metered
  connection, a tool that needs the internet to understand old code
  is a tool that does not work. This one does.

## Quickstart

```bash
# 1. Start Ollama and pull Gemma 3 (once)
ollama serve
ollama pull gemma3            # or: ollama pull gemma3:1b (small machines)

# 2. Raise the dead
python3 necromancer.py path/to/abandoned-project --model gemma3

# 3. Read the report, inspect the resurrected code
cat necromancer-out/haunted-audit-report.md
ls necromancer-out/revived/
```

Requirements: Python 3.10+, Ollama, and a local Gemma 3 model.
The tool itself uses **only the standard library** — no dependencies
to install, no supply chain to audit.

Try it without a model (previews the pipeline, contacts nothing):

```bash
python3 necromancer.py fixtures/haunted-legacy --dry-run
```

## CLI reference

```text
usage: necromancer [-h] [--output OUTPUT] [--model MODEL] [--host HOST]
                   [--only {all,autopsy,refactor}] [--dry-run]
                   [--allow-remote] [--force] [--max-file-kb MAX_FILE_KB]
                   [--timeout TIMEOUT] [--temperature TEMPERATURE] [--quiet]
                   [--version]
                   input

positional arguments:
  input                 Path to an abandoned project directory (or a single file)

options:
  --output, -o          Output directory (default: necromancer-out)
  --model               Ollama model tag (default: gemma3)
  --host                Ollama base URL (default: http://127.0.0.1:11434)
  --only                Run one stage only: all | autopsy | refactor
  --dry-run             Walk the pipeline without contacting the model
  --allow-remote        Allow a non-loopback Ollama host (code leaves this machine)
  --force               Ignore the cached manifest and re-run every file
  --max-file-kb         Skip files larger than this (KB, default: 200)
  --timeout             Per-call Ollama timeout in seconds (default: 600)
  --temperature         Sampling temperature (default: 0.2)
  --quiet, -q           Suppress progress output
```

Exit codes: `0` success · `2` usage/configuration error ·
`3` Ollama unreachable or model missing · `4` partial failure (some
files failed; the report lists them).

## What the tool scans — and what it refuses

Scanned: Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, C/C++,
Rust, C#, Shell. Skipped with a recorded reason: version-control and
dependency directories (`.git`, `node_modules`, `venv`, …), binaries,
files over the size cap, and unsupported extensions. The report
accounts for every skipped file, so a clean report cannot hide an
unexamined corner.

**Guardrails that are not optional:**

- The output directory may not be the input directory or inside it —
  resurrected files must never be scanned as new input.
- Files over 9,000 characters are autopsied but **not rewritten**:
  rewriting them chunk-by-chunk would silently break them, so the
  engine says so and leaves them for a human.
- A second run skips unchanged files (SHA-256 in the manifest) and
  restores their recorded findings — no wasted model calls, no
  silently different report.

## Outputs

```text
necromancer-out/
├── haunted-audit-report.md    # the report: vitals, findings, resurrections, séance log
├── revived/                   # resurrected code, mirroring the input tree
├── seance/                    # raw Gemma replies, verbatim, one per chunk
└── .necromancer-manifest.json # run record: hashes, findings, timings, verification
```

## How Gemma is used — honestly

Gemma 3 does the analysis and the drafting; a human does the
verification. The autopsy prompt requires findings as a fenced JSON
array (severity, category, title, line, evidence, explanation, fix),
so the report is rendered deterministically from structured data —
not from free prose that could drift. If a reply has no parseable
JSON, the prose is preserved and a parse warning is recorded; no
findings are invented to fill the gap.

A dedicated reviewer profile is provided for repeatable runs:

```bash
ollama create ghost-reviewer -f models/Modelfile.gemma3
python3 necromancer.py path/to/project --model ghost-reviewer
```

Prompt texts live in `necromancer.py` (`AUTOPSY_*`, `REFACTOR_*`,
`REPORT_*`) and are documented in `docs/prompts.md`.

## Honest limits

- **The model can be wrong.** Findings are claims, not proof. Every
  finding carries its evidence so a human can check it in seconds,
  and the report marks which files were verified (Python drafts must
  compile) and which were not.
- **The recorded 1b run echoed on rewrite.** In the séance recorded
  on 30 October 2026 (`docs/example-haunted-audit-report.md`), the
  `gemma3:1b` rewrite drafts repeated the redacted input verbatim —
  the dangerous patterns survived, and only compilation was verified.
  Treat every rewrite draft as unreviewed until a human diffs it.
  Line numbers in model findings are the model's own guesses and must
  be checked against the code; several findings in the recorded run
  were invented (a race condition in single-threaded code, a
  credential in a file that has none). The autopsy is strong; the
  curation is the product.
- **Rewrite coverage is bounded.** Very large files are autopsied
  only. Multi-language rewrites are drafted but only Python drafts
  are compile-verified; the rest are marked unverified, plainly.
- **Re-running with a different Gemma 3 size may produce different
  drafts.** That is expected. The preserved raw output makes any run
  auditable.
- **The tool never executes the revived code.** It compiles Python
  drafts and runs no project. Running resurrected code with real
  credentials is the operator's job, after rotating any secret the
  autopsy found exposed.

## Project layout

```text
legacy-code-necromancer/
├── necromancer.py              # the whole tool: scanner, filters, 3 engines, CLI
├── fixtures/haunted-legacy/    # deliberately haunted demo code (fake secrets only)
├── tests/test_necromancer.py   # 23 unit tests, mocked Ollama, no network
├── models/Modelfile.gemma3     # Gemma reviewer profile for Ollama
├── docs/prompts.md             # prompt documentation
└── examples/run-example.sh     # one-command demo
```

## License

MIT — see `LICENSE`.
