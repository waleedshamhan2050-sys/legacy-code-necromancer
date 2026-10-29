#!/usr/bin/env python3
"""The Legacy Code Necromancer — dissect and revive abandoned code with local Gemma 3.

A single-file, standard-library-only CLI. Point it at any abandoned
project directory and it runs the Necromancer Pipeline, entirely
through a Gemma 3 model served locally by Ollama:

1. **Code Autopsy** — every source file is examined for security
   vulnerabilities, deprecated APIs, and structural defects. Findings
   are returned as structured data (severity, category, file, line).
2. **Auto-Refactoring & Patching** — Gemma drafts a modern, clean,
   safe version of each file that fits in one model pass, preserving
   behaviour. Drafts are verified (Python files must compile) and
   written to ``<output>/revived/`` mirroring the input tree.
3. **Haunted Audit Report** — a Markdown report that wears the
   Halloween spirit of the "Ghost in the Machine" challenge on its
   sleeve while documenting the engineering precisely: project
   vitals, findings, resurrections, verification results, and a full
   séance log (model, timings, reproducibility).

Local-first and privacy-focused, by construction:

- The default Ollama endpoint is loopback (``http://127.0.0.1:11434``).
  A non-loopback host is refused unless ``--allow-remote`` is passed.
- ``SecretsFilter`` redacts hardcoded credentials, tokens, private
  keys, and high-entropy literals *before* any code reaches the model
  — the model never sees a secret, even locally.
- Raw model output is preserved verbatim under ``<output>/seance/``.
  Nothing is sent to any cloud service; there are no API keys.

Usage:
    ollama serve
    ollama pull gemma3            # or gemma3:1b on small machines

    python3 necromancer.py path/to/old-project --model gemma3
    python3 necromancer.py path/to/old-project --only autopsy
    python3 necromancer.py path/to/old-project --dry-run   # no model calls

Exit codes: 0 success, 2 usage/configuration error, 3 Ollama
unreachable or model missing, 4 partial failure (some files failed).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.0.0"

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "gemma3"
DEFAULT_TIMEOUT = 600
MAX_CHUNK_CHARS = 6000
MAX_REWRITE_CHARS = 9000

log = logging.getLogger("necromancer")


class NecromancerError(Exception):
    """Fatal, user-facing error (bad input, unreachable Ollama, ...)."""


class PartialFailure(Exception):
    """Raised when some files failed but the run produced output."""


# ---------------------------------------------------------------------------
# Secrets filter
# ---------------------------------------------------------------------------

# Assignment lines whose value must never reach the model.
_SECRET_ASSIGNMENT = re.compile(
    r"""(?im)^(?P<indent>\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*
        (?:token|api[_-]?key|secret|password|passwd|private[_-]?key|auth)
        [A-Za-z0-9_]*)\s*[:=].*$""",
    re.VERBOSE,
)

# Well-known credential shapes, anywhere in the text.
_KNOWN_PREFIXES = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9\-_]{16,}|"
    r"xox[baprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"
)

# A long quoted literal on a sensitive-looking line (fallback heuristic).
_LONG_LITERAL = re.compile(r"""(?m)^\s*\w*(key|token|secret|pwd|pass)\w*\s*=\s*(['"]).{16,}\2""", re.IGNORECASE)


@dataclass
class RedactionResult:
    text: str
    redacted_lines: int
    redacted_spans: int


def redact_secrets(code: str) -> RedactionResult:
    """Redact credential-looking content. The original values are never returned.

    Strategy, in order: (1) known credential prefixes anywhere in the
    text, (2) whole assignment lines for sensitive names, (3) long
    quoted literals on sensitive names. Lines already reading from the
    environment (``os.environ`` / ``getenv``) are left untouched.
    """
    spans = 0

    def _prefix_replace(match: re.Match[str]) -> str:
        nonlocal spans
        spans += 1
        return "***REDACTED***"

    code = _KNOWN_PREFIXES.sub(_prefix_replace, code)

    lines = 0
    out: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if (
            _SECRET_ASSIGNMENT.match(line)
            and "os.environ" not in line
            and "getenv" not in line
            and "getpass" not in line
        ):
            name = line.split("=", 1)[0].split(":")[0].strip()
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f'{indent}{name} = "***REDACTED***"')
            lines += 1
        elif _LONG_LITERAL.search(line) and "os.environ" not in line:
            out.append(re.sub(r"(['\"]).{16,}\1", r"\1***REDACTED***\1", line, count=1))
            lines += 1
        else:
            out.append(line)
    return RedactionResult("\n".join(out), lines, spans)


# ---------------------------------------------------------------------------
# Project scanning
# ---------------------------------------------------------------------------

LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".rs": "Rust",
    ".cs": "C#",
    ".sh": "Shell",
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules",
    "dist", "build", ".idea", ".vscode", ".tox", ".eggs", "target",
    "vendor", ".next", "coverage", ".pytest_cache",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".mp3",
    ".mp4", ".db", ".sqlite", ".sqlite3", ".pyc", ".class", ".o", ".a",
}


@dataclass
class SourceFile:
    path: Path           # absolute path on disk
    rel: str             # path relative to the project root (posix)
    language: str
    lines: int
    size_bytes: int
    sha256: str
    text: str = ""       # redacted text, filled by load()
    redacted_lines: int = 0
    redacted_spans: int = 0

    def load(self) -> "SourceFile":
        raw = self.path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        redacted = redact_secrets(text)
        self.text = redacted.text
        self.redacted_lines = redacted.redacted_lines
        self.redacted_spans = redacted.redacted_spans
        return self


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


@dataclass
class ScanResult:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (rel, reason)

    @property
    def total_lines(self) -> int:
        return sum(f.lines for f in self.files)


def scan_project(root: Path, *, max_file_kb: int = 200) -> ScanResult:
    """Walk a project tree, collecting scannable source files.

    Skips version-control metadata, dependency/vendor trees, caches,
    binary files, and files over ``max_file_kb``. Every skip is
    recorded with a reason so the report accounts for the whole tree.
    """
    if not root.exists():
        raise NecromancerError(f"Input path does not exist: {root}")
    root = root.resolve()
    result = ScanResult(root=root)
    candidates: list[Path] = []
    if root.is_file():
        candidates = [root]
        result.root = root.parent
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                candidates.append(Path(dirpath) / name)
    for path in candidates:
        rel = path.relative_to(result.root).as_posix()
        ext = path.suffix.lower()
        if ext in BINARY_EXTENSIONS:
            result.skipped.append((rel, "binary extension"))
            continue
        if path.stat().st_size > max_file_kb * 1024:
            result.skipped.append((rel, f"over {max_file_kb} KB size cap"))
            continue
        data = path.read_bytes()
        if _looks_binary(data):
            result.skipped.append((rel, "binary content (NUL byte)"))
            continue
        language = LANGUAGE_BY_EXTENSION.get(ext)
        if language is None:
            result.skipped.append((rel, "unsupported extension"))
            continue
        text = data.decode("utf-8", errors="replace")
        result.files.append(
            SourceFile(
                path=path.resolve(),
                rel=rel,
                language=language,
                lines=text.count("\n") + (0 if text.endswith("\n") or not text else 1),
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    return result


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    file_rel: str
    index: int       # 1-based
    total: int
    start_line: int  # 1-based, inclusive
    end_line: int    # inclusive
    text: str


def chunk_text(rel: str, text: str, *, limit: int = MAX_CHUNK_CHARS) -> list[Chunk]:
    """Split text into contiguous line ranges, each under ``limit`` chars.

    Chunks never overlap, so line references stay unambiguous. A single
    line longer than the limit becomes a chunk of its own.
    """
    lines = text.splitlines()
    chunks: list[Chunk] = []
    current: list[str] = []
    current_chars = 0
    start = 1
    for i, line in enumerate(lines, 1):
        if current and current_chars + len(line) + 1 > limit:
            chunks.append(Chunk(rel, len(chunks) + 1, 0, start, i - 1, "\n".join(current)))
            current, current_chars, start = [], 0, i
        current.append(line)
        current_chars += len(line) + 1
    if current or not chunks:
        chunks.append(Chunk(rel, len(chunks) + 1, 0, start, len(lines), "\n".join(current)))
    for chunk in chunks:
        chunk.total = len(chunks)
    return chunks


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

@dataclass
class CallRecord:
    model: str
    kind: str
    chars_sent: int
    chars_received: int
    duration_s: float
    dry_run: bool = False


class OllamaClient:
    """Minimal Ollama chat client (standard library only)."""

    def __init__(
        self,
        host: str,
        model: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        temperature: float = 0.2,
        num_ctx: int = 8192,
        retries: int = 2,
        dry_run: bool = False,
        allow_remote: bool = False,
    ) -> None:
        parsed = urllib.parse.urlparse(host)
        if parsed.hostname not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
            raise NecromancerError(
                f"Refusing non-loopback Ollama host {host!r} without --allow-remote: "
                "revival code must stay on this machine."
            )
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.retries = retries
        self.dry_run = dry_run
        self.calls: list[CallRecord] = []

    def check(self) -> list[str]:
        """Return available model tags, or raise NecromancerError."""
        if self.dry_run:
            return [self.model]
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - surfaced as a clean error
            raise NecromancerError(
                f"Cannot reach Ollama at {self.host}: {exc}. "
                "Start it with: ollama serve"
            ) from exc
        return [m["name"] for m in body.get("models", [])]

    def ensure_model(self) -> None:
        models = self.check()
        wanted = {self.model, f"{self.model}:latest"}
        if not wanted & set(models):
            raise NecromancerError(
                f"Model {self.model!r} is not available locally. "
                f"Available: {models or 'none'}. Pull it with: ollama pull {self.model}"
            )

    def chat(self, kind: str, system: str, user: str) -> str:
        started = time.monotonic()
        if self.dry_run:
            reply = (
                f"[dry-run] {kind} call to {self.model}: "
                f"system={len(system)} chars, user={len(user)} chars. "
                "No model was contacted."
            )
            self.calls.append(
                CallRecord(self.model, kind, len(system) + len(user), len(reply),
                           time.monotonic() - started, dry_run=True)
            )
            return reply
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": self.temperature, "num_ctx": self.num_ctx},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                content = body["message"]["content"]
                self.calls.append(
                    CallRecord(self.model, kind, len(system) + len(user),
                               len(content), time.monotonic() - started)
                )
                return content
            except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
                last_error = exc
                time.sleep(5 * (attempt + 1))
        raise NecromancerError(
            f"Ollama {kind} call failed after {self.retries + 1} attempts: {last_error}"
        )


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

AUTOPSY_SYSTEM = (
    "You are a senior code pathologist performing an autopsy on abandoned "
    "software. Be concrete, cite file and line numbers, and prefer "
    "findings verifiable from the code over speculation. Never repeat a "
    "credential value; write SECRET-REDACTED if one is present."
)

AUTOPSY_USER_TEMPLATE = """Perform a code autopsy on this file from an abandoned project.
The project has been dead for years; your job is to determine what
killed it and what would kill it again if it were revived unchanged.

File: {rel} ({language}, chunk {index} of {total}, lines {start}-{end})
```{fence}
{code}
```

First, give a short prose verdict (2-4 sentences): what is this file
for, and what is its overall state?

Then list EVERY finding as a fenced ```json block containing a JSON
array. Each finding has exactly these fields:
- "severity": one of "Critical", "High", "Medium", "Low"
- "category": one of "security", "deprecated-api", "correctness",
  "reliability", "maintainability"
- "title": short name, e.g. "Hardcoded credential"
- "line": the line number inside the chunk (1-based), or null
- "evidence": the exact code fragment (at most 3 lines)
- "explanation": why it matters, one or two sentences
- "fix": the concrete fix, one sentence

Cover: hardcoded secrets and auth bypasses; injection, unsafe
deserialisation, path traversal, SSRF; deprecated or removed APIs;
timezone and encoding errors; races and blocking I/O in async code;
uncaught exceptions; missing retries/backoff for rate limits; unpinned
dependencies; dead code. If a category has no findings, say so in the
prose verdict and leave it out of the JSON. An empty array is a valid
answer for a healthy file — do not invent findings.
"""

REFACTOR_SYSTEM = (
    "You are a senior engineer resurrecting abandoned code. Preserve "
    "the original behaviour and user-visible messages. Prefer the "
    "smallest change that fixes a real defect."
)

REFACTOR_USER_TEMPLATE = """Resurrect this file: produce a modern, clean, safe equivalent in
{language}. The file comes from an abandoned project and must keep
working the way its users expect.

File: {rel} ({language}, {lines} lines)
Autopsy findings to address:
{findings}

```{fence}
{code}
```

Requirements:
- Same behaviour and same user-visible messages, unless a message
  leaks internal errors (then use a generic message).
- Secrets only from environment variables; fail fast with a clear
  error when a required variable is missing.
- Timezone-aware datetimes (UTC) where dates are involved; no naive
  local-time arithmetic.
- No blocking I/O inside async code; honour rate-limit signals with
  backoff; no bare exception handlers that hide failures.
- Type hints and docstrings where the language supports them; no new
  third-party dependencies beyond the ones already used.
- Return ONLY a fenced {fence} code block containing the complete
  file. No explanation outside the code block.
"""

REPORT_SYSTEM = (
    "You are a technical writer documenting a code resurrection. "
    "Write clear, honest release notes: what changed, what stayed the "
    "same, and what the operator must do before deploying."
)

REPORT_USER_TEMPLATE = """Write the "Cause of Death" and "Resurrection Notes" sections of a
haunted audit report, in Markdown, from the autopsy findings and the
revival summary below. Be specific: name each major fix, why it
mattered, and anything that breaks compatibility. End with a
"Before you deploy" checklist covering secrets rotation, environment
variables, and data migration.

Findings summary:
{findings}

Revival summary:
{revival}
"""


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    file: str
    line: int | None
    evidence: str
    explanation: str
    fix: str

    def sort_key(self) -> tuple[int, str, int]:
        return (
            SEVERITY_ORDER.get(self.severity, 9),
            self.file,
            self.line or 0,
        )


def extract_json_block(text: str) -> str | None:
    match = re.search(r"```json\s*\n(.*?)```", text, re.DOTALL)
    return match.group(1) if match else None


def parse_findings(text: str, *, file_rel: str) -> tuple[list[Finding], str]:
    """Parse Gemma's autopsy reply into findings + prose verdict.

    The prose is everything outside the JSON block. If the JSON block
    is missing or malformed, all findings are lost but the prose is
    preserved and the caller records a parse warning.
    """
    block = extract_json_block(text)
    prose = re.sub(r"```json\s*\n.*?```", "", text, flags=re.DOTALL).strip()
    findings: list[Finding] = []
    if block is None:
        return findings, prose
    try:
        raw = json.loads(block)
    except json.JSONDecodeError:
        return findings, prose
    if not isinstance(raw, list):
        return findings, prose
    for item in raw:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "Low")).capitalize()
        if severity not in SEVERITY_ORDER:
            severity = "Low"
        try:
            line = item.get("line")
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        findings.append(
            Finding(
                severity=severity,
                category=str(item.get("category", "maintainability")),
                title=str(item.get("title", "Untitled finding")),
                file=file_rel,
                line=line,
                evidence=str(item.get("evidence", ""))[:500],
                explanation=str(item.get("explanation", "")),
                fix=str(item.get("fix", "")),
            )
        )
    return findings, prose


def extract_code_block(text: str, fence: str) -> str | None:
    """Return the first fenced block for ``fence`` (or any fence as fallback)."""
    match = re.search(rf"```{re.escape(fence)}\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    return match.group(1) if match else None


FENCE_BY_LANGUAGE = {
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Go": "go",
    "Java": "java",
    "Ruby": "ruby",
    "PHP": "php",
    "C": "c",
    "C++": "cpp",
    "Rust": "rust",
    "C#": "csharp",
    "Shell": "bash",
}


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

@dataclass
class FileOutcome:
    source: SourceFile
    verdict: str = ""
    findings: list[Finding] = field(default_factory=list)
    parse_warning: bool = False
    autopsy_seconds: float = 0.0
    refactor_status: str = "skipped"  # rewritten | too-large | failed | skipped
    refactor_seconds: float = 0.0
    revived_path: str = ""
    verified: bool | None = None
    error: str = ""


def _fence(language: str) -> str:
    return FENCE_BY_LANGUAGE.get(language, "")


def run_autopsy(
    source: SourceFile, client: OllamaClient, *, seance_dir: Path
) -> tuple[str, list[Finding], bool, float]:
    """Autopsy one file, chunk by chunk. Returns verdict, findings, warning, seconds."""
    started = time.monotonic()
    chunks = chunk_text(source.rel, source.text)
    verdicts: list[str] = []
    findings: list[Finding] = []
    warning = False
    for chunk in chunks:
        fence = _fence(source.language)
        reply = client.chat(
            "autopsy",
            AUTOPSY_SYSTEM,
            AUTOPSY_USER_TEMPLATE.format(
                rel=source.rel,
                language=source.language,
                index=chunk.index,
                total=chunk.total,
                start=chunk.start_line,
                end=chunk.end_line,
                fence=fence,
                code=chunk.text,
            ),
        )
        (seance_dir / f"{source.path.stem}.chunk{chunk.index}.autopsy.md").write_text(
            reply, encoding="utf-8"
        )
        parsed, prose = parse_findings(reply, file_rel=source.rel)
        # Convert chunk-relative lines to file-absolute lines.
        for finding in parsed:
            if finding.line is not None:
                finding.line = finding.line + chunk.start_line - 1
        if extract_json_block(reply) is None and not client.dry_run:
            warning = True
        verdicts.append(prose)
        findings.extend(parsed)
    findings.sort(key=lambda f: f.sort_key())
    return "\n\n".join(v for v in verdicts if v), findings, warning, time.monotonic() - started


def run_refactor(
    source: SourceFile,
    findings: list[Finding],
    client: OllamaClient,
    *,
    seance_dir: Path,
    revived_root: Path,
) -> tuple[str, bool | None, float, str]:
    """Rewrite one file with Gemma. Returns status, verified, seconds, out-rel-path.

    Files over ``MAX_REWRITE_CHARS`` are left for a human: rewriting
    them chunk-by-chunk would silently break the file, so the engine
    says so instead of guessing.
    """
    started = time.monotonic()
    if client.dry_run:
        # A dry run previews prompts; it must not fabricate rewrite
        # drafts or report stub replies as failures.
        return "skipped", None, time.monotonic() - started, ""
    if len(source.text) > MAX_REWRITE_CHARS:
        return "too-large", None, time.monotonic() - started, ""
    findings_text = (
        "\n".join(
            f"- [{f.severity}] {f.title} (line {f.line}): {f.explanation} Fix: {f.fix}"
            for f in findings
        )
        or "No findings — keep the file as-is, modernising only style where safe."
    )
    fence = _fence(source.language)
    reply = client.chat(
        "refactor",
        REFACTOR_SYSTEM,
        REFACTOR_USER_TEMPLATE.format(
            rel=source.rel,
            language=source.language,
            lines=source.lines,
            findings=findings_text,
            fence=fence,
            code=source.text,
        ),
    )
    (seance_dir / f"{source.path.stem}.refactor.md").write_text(reply, encoding="utf-8")
    code = extract_code_block(reply, fence)
    if code is None:
        return "failed", False, time.monotonic() - started, ""
    out_path = revived_root / source.rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(code.rstrip() + "\n", encoding="utf-8")
    verified: bool | None = None
    if source.language == "Python":
        import py_compile

        try:
            py_compile.compile(str(out_path), doraise=True, quiet=1)
            verified = True
        except py_compile.PyCompileError:
            verified = False
    return "rewritten", verified, time.monotonic() - started, out_path.relative_to(revived_root).as_posix()


# ---------------------------------------------------------------------------
# Haunted audit report
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {"Critical": "💀", "High": "🩸", "Medium": "⚠️", "Low": "🕯️"}


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings. The corpse was healthier than expected — the cause of death lies elsewhere (abandonment, not rot).\n"
    rows = ["| Severity | File | Line | Finding | Category |", "|---|---|---|---|---|"]
    for f in findings:
        title = f.title.replace("|", "\\|")
        rows.append(
            f"| {SEVERITY_EMOJI.get(f.severity, '')} {f.severity} | `{f.file}` | "
            f"{f.line or '—'} | {title} | {f.category} |"
        )
    return "\n".join(rows) + "\n"


def render_report(
    *,
    project_name: str,
    scan: ScanResult,
    outcomes: list[FileOutcome],
    client: OllamaClient,
    started_at: str,
    duration_s: float,
    dry_run: bool,
    report_prose: str,
) -> str:
    findings = [f for o in outcomes for f in o.findings]
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    rewritten = [o for o in outcomes if o.refactor_status == "rewritten"]
    too_large = [o for o in outcomes if o.refactor_status == "too-large"]
    failed = [o for o in outcomes if o.error]
    secrets_total = sum(
        getattr(o.source, "redacted_lines", 0) + getattr(o.source, "redacted_spans", 0)
        for o in outcomes
    )
    lines = [
        f"# 👻 Haunted Audit Report — {project_name}",
        "",
        "> *The dead code walked again on Halloween night. This report is the "
        "autopsy, the resurrection, and the séance log — written so a human "
        "can verify every claim against the raw model output preserved in "
        "`seance/`.*",
        "",
        f"- **Examined:** {started_at} (UTC)",
        f"- **Séance duration:** {duration_s:.1f}s",
        f"- **Model:** `{client.model}` via Ollama at `{client.host}` "
        f"({'dry run — no model was contacted' if dry_run else 'local inference only'})",
        f"- **Tool:** The Legacy Code Necromancer v{__version__}",
        "",
        "## ☠️ The Corpse — project vitals",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Source files examined | {len(scan.files)} |",
        f"| Total lines | {scan.total_lines} |",
        f"| Languages | {', '.join(sorted({f.language for f in scan.files})) or '—'} |",
        f"| Files skipped | {len(scan.skipped)} |",
        f"| Secret lines/spans redacted before prompting | {secrets_total} |",
        f"| Findings | {len(findings)} "
        f"(💀 {counts['Critical']} · 🩸 {counts['High']} · ⚠️ {counts['Medium']} · 🕯️ {counts['Low']}) |",
        f"| Files resurrected | {len(rewritten)} |",
        "",
    ]
    if scan.skipped:
        lines += ["### Left in the grave (skipped files)", ""]
        for rel, reason in scan.skipped:
            lines.append(f"- `{rel}` — {reason}")
        lines.append("")
    lines += [
        "## 🔍 Cause of Death",
        "",
        report_prose.strip() or "_The model returned no prose verdict._",
        "",
        "## 🩸 Wounds — findings",
        "",
        _findings_table(findings),
    ]
    for outcome in outcomes:
        if not outcome.findings and not outcome.verdict:
            continue
        lines += [f"### `{outcome.source.rel}`", ""]
        if outcome.verdict:
            lines.append(outcome.verdict.strip())
            lines.append("")
        for f in outcome.findings:
            lines.append(
                f"- **{SEVERITY_EMOJI.get(f.severity, '')} {f.severity} — {f.title}**"
                + (f" (line {f.line})" if f.line else "")
                + f" *[{f.category}]*"
            )
            if f.evidence.strip():
                lines.append(f"  - Evidence: `{f.evidence.strip()[:200]}`")
            lines.append(f"  - {f.explanation}")
            lines.append(f"  - Fix: {f.fix}")
        if outcome.parse_warning:
            lines.append(
                "- ⚠️ The model's reply for this file had no parseable JSON "
                "block; its prose verdict is preserved in `seance/` and no "
                "structured findings were extracted from it."
            )
        lines.append("")
    lines += [
        "## 🧟 The Resurrection — what was rewritten",
        "",
    ]
    if rewritten:
        lines += ["| Original | Resurrected | Verified |", "|---|---|---|"]
        for o in rewritten:
            mark = "✅ compiles" if o.verified else ("❌ does not compile" if o.verified is False else "—")
            lines.append(f"| `{o.source.rel}` | `{o.revived_path}` | {mark} |")
        lines.append("")
    else:
        lines.append("No files were rewritten in this run.\n")
    if too_large:
        lines.append(
            "The following files were too large for a single safe rewrite pass "
            f"(over {MAX_REWRITE_CHARS} characters) and were left for a human — "
            "rewriting them chunk-by-chunk would silently break them:"
        )
        lines.append("")
        for o in too_large:
            lines.append(f"- `{o.source.rel}` ({o.source.lines} lines)")
        lines.append("")
    if failed:
        lines.append("### Failed exhumations")
        lines.append("")
        for o in failed:
            lines.append(f"- `{o.source.rel}`: {o.error}")
        lines.append("")
    total_sent = sum(c.chars_sent for c in client.calls)
    total_received = sum(c.chars_received for c in client.calls)
    lines += [
        "## 🔮 The Séance Log — model calls",
        "",
        f"- Model calls: {len(client.calls)} "
        f"({sum(1 for c in client.calls if c.kind == 'autopsy')} autopsy, "
        f"{sum(1 for c in client.calls if c.kind == 'refactor')} refactor, "
        f"{sum(1 for c in client.calls if c.kind == 'report')} report)",
        f"- Characters sent to the model: {total_sent}",
        f"- Characters received: {total_received}",
        "- Raw model output: preserved verbatim under `seance/` — every "
        "finding in this report can be traced to the reply that produced it.",
        "- Network: none. All calls went to a loopback Ollama endpoint; "
        "no code left this machine.",
        "",
        "## 📜 Reproducibility",
        "",
        "```bash",
        "ollama serve",
        f"ollama pull {client.model}",
        "python3 necromancer.py <project-path> "
        f"--model {client.model} --output <output-dir>",
        "```",
        "",
        "Prompts: see `docs/prompts.md` in the Necromancer repository. "
        "Re-running with a different Gemma 3 size may produce different "
        "drafts — that is expected, and the preserved raw output makes it "
        "auditable.",
        "",
        "---",
        "",
        "*Happy Hacktoberfest, and rest in peace — or rise again.* 🎃",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def write_manifest(
    out_dir: Path,
    *,
    scan: ScanResult,
    outcomes: list[FileOutcome],
    client: OllamaClient,
    started_at: str,
    duration_s: float,
    dry_run: bool,
) -> dict:
    manifest = {
        "tool": f"legacy-code-necromancer v{__version__}",
        "started_at_utc": started_at,
        "duration_s": round(duration_s, 1),
        "model": client.model,
        "host": client.host,
        "dry_run": dry_run,
        "project_root": str(scan.root),
        "files": [],
    }
    for outcome in outcomes:
        source = outcome.source
        manifest["files"].append(
            {
                "path": source.rel,
                "language": source.language,
                "lines": source.lines,
                "sha256": source.sha256,
                "secrets_redacted_lines": getattr(source, "redacted_lines", 0),
                "secrets_redacted_spans": getattr(source, "redacted_spans", 0),
                "verdict": outcome.verdict,
                "findings": [asdict(f) for f in outcome.findings],
                "parse_warning": outcome.parse_warning,
                "autopsy_seconds": round(outcome.autopsy_seconds, 1),
                "refactor_status": outcome.refactor_status,
                "refactor_seconds": round(outcome.refactor_seconds, 1),
                "revived_path": outcome.revived_path,
                "verified": outcome.verified,
                "error": outcome.error,
            }
        )
    (out_dir / ".necromancer-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


def load_manifest(out_dir: Path) -> dict | None:
    path = out_dir / ".necromancer-manifest.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Pipeline + CLI
# ---------------------------------------------------------------------------

def run_pipeline(
    input_path: Path,
    out_dir: Path,
    client: OllamaClient,
    *,
    only: str,
    force: bool,
    max_file_kb: int,
) -> tuple[ScanResult, list[FileOutcome], float, str]:
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    started = time.monotonic()
    scan = scan_project(input_path, max_file_kb=max_file_kb)
    if not scan.files:
        raise NecromancerError(
            f"No scannable source files found under {input_path}. "
            f"Skipped: {len(scan.skipped)} file(s) (unsupported/binary/oversized)."
        )
    seance_dir = out_dir / "seance"
    revived_root = out_dir / "revived"
    seance_dir.mkdir(parents=True, exist_ok=True)

    previous = None if force else load_manifest(out_dir)
    previous_by_hash: dict[str, dict] = {}
    if previous:
        for entry in previous.get("files", []):
            previous_by_hash[entry["path"]] = entry

    outcomes: list[FileOutcome] = []
    failures = 0
    for source in scan.files:
        outcome = FileOutcome(source=source)
        cached = previous_by_hash.get(source.rel)
        if cached and cached.get("sha256") == source.sha256 and not cached.get("error"):
            # Unchanged since the last run: restore the recorded outcome
            # (verdict + findings are stored in the manifest) without
            # spending model calls again.
            log.info("Skipping unchanged file (cached): %s", source.rel)
            outcome.verdict = cached.get("verdict", "")
            outcome.findings = [
                Finding(**item) for item in cached.get("findings", [])
                if isinstance(item, dict)
            ]
            source.redacted_lines = cached.get("secrets_redacted_lines", 0)
            source.redacted_spans = cached.get("secrets_redacted_spans", 0)
            outcome.refactor_status = cached.get("refactor_status", "skipped")
            outcome.revived_path = cached.get("revived_path", "")
            outcome.verified = cached.get("verified")
            outcomes.append(outcome)
            continue
        try:
            source.load()
        except OSError as exc:
            outcome.error = f"Cannot read file: {exc}"
            failures += 1
            outcomes.append(outcome)
            continue
        try:
            if only in ("all", "autopsy"):
                verdict, findings, warning, seconds = run_autopsy(
                    source, client, seance_dir=seance_dir
                )
                outcome.verdict, outcome.findings = verdict, findings
                outcome.parse_warning, outcome.autopsy_seconds = warning, seconds
            if only in ("all", "refactor"):
                status, verified, seconds, rel_path = run_refactor(
                    source,
                    outcome.findings,
                    client,
                    seance_dir=seance_dir,
                    revived_root=revived_root,
                )
                outcome.refactor_status, outcome.verified = status, verified
                outcome.refactor_seconds, outcome.revived_path = seconds, rel_path
        except NecromancerError as exc:
            outcome.error = str(exc)
            failures += 1
        outcomes.append(outcome)

    duration_s = time.monotonic() - started
    if failures and failures == len(scan.files):
        raise NecromancerError(
            f"All {failures} file(s) failed. First error: {outcomes[0].error}"
        )
    return scan, outcomes, duration_s, started_at


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="necromancer",
        description=(
            "The Legacy Code Necromancer: dissect and revive abandoned code "
            "with a local Gemma 3 model via Ollama. Local-first, no cloud."
        ),
    )
    parser.add_argument("input", help="Path to an abandoned project directory (or a single file)")
    parser.add_argument("--output", "-o", default="necromancer-out",
                        help="Output directory (default: necromancer-out)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Ollama model tag (default: gemma3)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="Ollama base URL (default: loopback only)")
    parser.add_argument("--only", default="all", choices=["all", "autopsy", "refactor"],
                        help="Run one pipeline stage only (default: all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Walk the pipeline without contacting the model")
    parser.add_argument("--allow-remote", action="store_true",
                        help="Allow a non-loopback Ollama host (code leaves this machine)")
    parser.add_argument("--force", action="store_true",
                        help="Ignore the cached manifest and re-run every file")
    parser.add_argument("--max-file-kb", type=int, default=200,
                        help="Skip files larger than this (KB, default: 200)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Per-call Ollama timeout in seconds (default: 600)")
    parser.add_argument("--temperature", type=float, default=0.2,
                        help="Sampling temperature (default: 0.2)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
    )
    input_path = Path(args.input)
    out_dir = Path(args.output).resolve()
    try:
        if out_dir == input_path.resolve() or out_dir.is_relative_to(input_path.resolve()):
            raise NecromancerError(
                "Output directory must not be the input directory or inside it: "
                "the revived files would be scanned as new input on the next run."
            )
        client = OllamaClient(
            args.host,
            args.model,
            timeout=args.timeout,
            temperature=args.temperature,
            dry_run=args.dry_run,
            allow_remote=args.allow_remote,
        )
        if not args.dry_run:
            client.ensure_model()
        scan, outcomes, duration_s, started_at = run_pipeline(
            input_path,
            out_dir,
            client,
            only=args.only,
            force=args.force,
            max_file_kb=args.max_file_kb,
        )
    except NecromancerError as exc:
        print(f"necromancer: error: {exc}", file=sys.stderr)
        return 2

    # Report prose (skipped in dry-run and in single-stage runs without findings).
    report_prose = ""
    if not args.dry_run and args.only in ("all", "autopsy"):
        findings_text = "\n".join(
            f"- [{f.severity}] {f.title} ({f.file}:{f.line}): {f.explanation}"
            for o in outcomes
            for f in o.findings
        ) or "No findings."
        revival_text = "; ".join(
            f"{o.source.rel}: {o.refactor_status}"
            + (f" (verified={o.verified})" if o.verified is not None else "")
            for o in outcomes
        )
        try:
            report_prose = client.chat(
                "report",
                REPORT_SYSTEM,
                REPORT_USER_TEMPLATE.format(findings=findings_text, revival=revival_text),
            )
        except NecromancerError as exc:
            log.warning("Report prose generation failed: %s", exc)
            report_prose = ""

    out_dir.mkdir(parents=True, exist_ok=True)
    report = render_report(
        project_name=input_path.resolve().name,
        scan=scan,
        outcomes=outcomes,
        client=client,
        started_at=started_at,
        duration_s=duration_s,
        dry_run=args.dry_run,
        report_prose=report_prose,
    )
    (out_dir / "haunted-audit-report.md").write_text(report, encoding="utf-8")
    write_manifest(
        out_dir,
        scan=scan,
        outcomes=outcomes,
        client=client,
        started_at=started_at,
        duration_s=duration_s,
        dry_run=args.dry_run,
    )

    total_findings = sum(len(o.findings) for o in outcomes)
    rewritten = sum(1 for o in outcomes if o.refactor_status == "rewritten")
    failed = sum(1 for o in outcomes if o.error)
    print(f"Exhumed {len(scan.files)} file(s), {total_findings} finding(s), "
          f"{rewritten} resurrected, {failed} failed.")
    print(f"Report: {out_dir / 'haunted-audit-report.md'}")
    if rewritten:
        print(f"Revived code: {out_dir / 'revived'}")
    if failed:
        print(f"necromancer: warning: {failed} file(s) failed; see the report.", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
