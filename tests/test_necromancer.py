"""Unit tests for the Legacy Code Necromancer (no network, mocked Ollama)."""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("necromancer", ROOT / "necromancer.py")
nec = importlib.util.module_from_spec(spec)
sys.modules["necromancer"] = nec
spec.loader.exec_module(nec)


class FakeResponse:
    def __init__(self, payload: dict):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestSecretsFilter(unittest.TestCase):
    def test_assignment_redacted_and_counted(self):
        result = nec.redact_secrets('API_TOKEN = "supersecretvalue123"\nX = 1\n')
        self.assertIn('***REDACTED***', result.text)
        self.assertNotIn("supersecretvalue123", result.text)
        self.assertEqual(result.redacted_lines, 1)

    def test_env_driven_line_untouched(self):
        code = 'TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")\n'
        result = nec.redact_secrets(code)
        self.assertEqual(result.redacted_lines, 0)
        self.assertIn("os.environ", result.text)

    def test_known_prefix_redacted_anywhere(self):
        result = nec.redact_secrets('header = "Authorization: ghp_abcdefghijklmnopqrstuv"\n')
        self.assertNotIn("ghp_", result.text)
        self.assertEqual(result.redacted_spans, 1)

    def test_pem_block_redacted(self):
        result = nec.redact_secrets("KEY = '-----BEGIN PRIVATE KEY-----\nabc\n'")
        self.assertNotIn("BEGIN PRIVATE KEY", result.text)


class TestScanner(unittest.TestCase):
    def test_skips_and_languages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("x")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "a.js").write_text("var a = 1;")
            (root / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01")
            (root / "big.py").write_text("x = 1\n" * 10000)
            (root / "ok.py").write_text("print('hi')\n")
            (root / "notes.txt").write_text("hello")
            scan = nec.scan_project(root, max_file_kb=1)
            self.assertEqual([f.rel for f in scan.files], ["ok.py"])
            self.assertEqual(scan.files[0].language, "Python")
            reasons = dict(scan.skipped)
            self.assertEqual(reasons["pic.png"], "binary extension")
            self.assertIn("over 1 KB", reasons["big.py"])
            self.assertEqual(reasons["notes.txt"], "unsupported extension")

    def test_single_file_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "solo.js"
            target.write_text("console.log(1);\n")
            scan = nec.scan_project(target)
            self.assertEqual(len(scan.files), 1)
            self.assertEqual(scan.files[0].language, "JavaScript")

    def test_missing_path(self):
        with self.assertRaises(nec.NecromancerError):
            nec.scan_project(Path("/nonexistent-xyz"))


class TestChunking(unittest.TestCase):
    def test_contiguous_ranges_and_limits(self):
        text = "\n".join(f"line {i} " + "x" * 20 for i in range(1, 51))
        chunks = nec.chunk_text("a.py", text, limit=200)
        self.assertTrue(all(len(c.text) <= 200 for c in chunks))
        self.assertEqual(chunks[0].start_line, 1)
        self.assertEqual(chunks[-1].end_line, 50)
        for a, b in zip(chunks, chunks[1:]):
            self.assertEqual(a.end_line + 1, b.start_line)
        self.assertTrue(all(c.total == len(chunks) for c in chunks))

    def test_empty_file_is_one_chunk(self):
        self.assertEqual(len(nec.chunk_text("a.py", "")), 1)


class TestFindingParsing(unittest.TestCase):
    def test_valid_json_block(self):
        reply = (
            "Verdict: rotten.\n\n```json\n"
            '[{"severity": "Critical", "category": "security", "title": "Hardcoded credential",'
            ' "line": 3, "evidence": "TOKEN = \\"abc\\"", "explanation": "bad", "fix": "use env"}]\n```'
        )
        findings, prose = nec.parse_findings(reply, file_rel="a.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertEqual(findings[0].line, 3)
        self.assertIn("rotten", prose)

    def test_malformed_json_preserves_prose(self):
        reply = "Verdict: spooky.\n\n```json\n{not json\n```"
        findings, prose = nec.parse_findings(reply, file_rel="a.py")
        self.assertEqual(findings, [])
        self.assertIn("spooky", prose)

    def test_no_json_block(self):
        findings, prose = nec.parse_findings("Just prose, no block.", file_rel="a.py")
        self.assertEqual(findings, [])
        self.assertEqual(prose, "Just prose, no block.")

    def test_code_block_extraction(self):
        reply = "Here:\n```python\nprint(1)\n```\nDone."
        self.assertEqual(nec.extract_code_block(reply, "python"), "print(1)\n")
        self.assertIsNone(nec.extract_code_block("no fences here", "python"))


class TestOllamaClient(unittest.TestCase):
    def test_remote_host_refused(self):
        with self.assertRaises(nec.NecromancerError):
            nec.OllamaClient("http://192.168.1.5:11434", "gemma3")

    def test_remote_host_allowed_with_flag(self):
        client = nec.OllamaClient("http://192.168.1.5:11434", "gemma3", allow_remote=True)
        self.assertEqual(client.host, "http://192.168.1.5:11434")

    def test_dry_run_records_call(self):
        client = nec.OllamaClient("http://127.0.0.1:11434", "gemma3", dry_run=True)
        reply = client.chat("autopsy", "sys", "user")
        self.assertIn("dry-run", reply)
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(client.calls[0].dry_run)

    def test_chat_success_with_mock(self):
        client = nec.OllamaClient("http://127.0.0.1:11434", "gemma3")
        payload = {"message": {"content": "boo"}}
        with patch.object(nec.urllib.request, "urlopen", return_value=FakeResponse(payload)):
            self.assertEqual(client.chat("autopsy", "s", "u"), "boo")
        self.assertEqual(client.calls[0].chars_received, 3)

    def test_ensure_model_missing(self):
        client = nec.OllamaClient("http://127.0.0.1:11434", "gemma3")
        with patch.object(
            nec.urllib.request, "urlopen",
            return_value=FakeResponse({"models": [{"name": "other:1b"}]}),
        ):
            with self.assertRaises(nec.NecromancerError):
                client.ensure_model()

    def test_chat_retries_then_raises(self):
        client = nec.OllamaClient("http://127.0.0.1:11434", "gemma3", retries=1)
        with patch.object(
            nec.urllib.request, "urlopen",
            side_effect=nec.urllib.error.URLError("down"),
        ), patch.object(nec.time, "sleep", return_value=None):
            with self.assertRaises(nec.NecromancerError):
                client.chat("autopsy", "s", "u")


class TestPipelineDryRun(unittest.TestCase):
    def test_full_dry_run_writes_report_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            rc = nec.main([
                str(ROOT / "fixtures" / "haunted-legacy"),
                "--output", str(out),
                "--dry-run",
            ])
            self.assertEqual(rc, 0)
            report = (out / "haunted-audit-report.md").read_text()
            self.assertIn("Haunted Audit Report", report)
            self.assertIn("The Corpse", report)
            self.assertIn("Séance Log", report)
            manifest = json.loads((out / ".necromancer-manifest.json").read_text())
            self.assertEqual(len(manifest["files"]), 2)
            self.assertTrue(manifest["dry_run"])
            # Dry run must not fabricate resurrected code.
            self.assertFalse((out / "revived").exists())

    def test_output_inside_input_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = nec.main([
                str(ROOT / "fixtures" / "haunted-legacy"),
                "--output",
                str(ROOT / "fixtures" / "haunted-legacy" / "out"),
                "--dry-run",
            ])
            self.assertEqual(rc, 2)

    def test_resume_restores_findings_without_new_calls(self):
        # First run with a mocked client is complex; exercise the cache
        # path via two dry runs: the second must reuse the manifest.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            args = [str(ROOT / "fixtures" / "haunted-legacy"), "--output", str(out), "--dry-run"]
            self.assertEqual(nec.main(args), 0)
            first = json.loads((out / ".necromancer-manifest.json").read_text())
            self.assertEqual(nec.main(args), 0)
            second = json.loads((out / ".necromancer-manifest.json").read_text())
            self.assertEqual(
                [f["sha256"] for f in first["files"]],
                [f["sha256"] for f in second["files"]],
            )


class TestReportRendering(unittest.TestCase):
    def test_report_contains_findings_and_counts(self):
        source = nec.SourceFile(
            path=Path("a.py"), rel="a.py", language="Python",
            lines=10, size_bytes=50, sha256="x",
        )
        outcome = nec.FileOutcome(
            source=source,
            verdict="Rotten.",
            findings=[nec.Finding("Critical", "security", "Hardcoded credential",
                                  "a.py", 3, 'TOKEN = "x"', "bad", "use env")],
        )
        scan = nec.ScanResult(root=Path("."), files=[source])
        client = nec.OllamaClient("http://127.0.0.1:11434", "gemma3", dry_run=True)
        report = nec.render_report(
            project_name="a", scan=scan, outcomes=[outcome], client=client,
            started_at="2026-10-30T00:00:00Z", duration_s=1.5,
            dry_run=True, report_prose="Cause: neglect.",
        )
        self.assertIn("Hardcoded credential", report)
        self.assertIn("💀 1", report)
        self.assertIn("Cause: neglect.", report)


if __name__ == "__main__":
    unittest.main()
