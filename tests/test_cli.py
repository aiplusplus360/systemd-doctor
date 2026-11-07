import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from systemddoctor.cli import main

BAD = """[Unit]
Description=api
After=network-online.target

[Service]
ExecStart=api serve
Restart=always
StandardOutput=null

[Install]
WantedBy=multi-user.target
"""

GOOD = """[Unit]
Description=api
Documentation=https://runbooks.example/api

[Service]
Type=exec
User=api
ExecStart=/opt/api/bin/serve
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
"""


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bad = Path(self.tmp.name) / "api.service"
        self.bad.write_text(BAD, encoding="utf-8")
        self.good = Path(self.tmp.name) / "worker.service"
        self.good.write_text(GOOD, encoding="utf-8")

    def test_check_fails_on_error(self):
        code, out, _ = run(["check", str(self.bad)])
        self.assertEqual(code, 1)
        self.assertIn("runs-as-root", out)
        self.assertIn("ERROR", out)

    def test_check_json(self):
        code, out, _ = run(["check", str(self.bad), "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["summary"]["errors"], 1)
        self.assertEqual(payload["units"][0]["source"], str(self.bad))

    def test_good_unit_exits_zero(self):
        code, out, _ = run(["check", str(self.good)])
        self.assertEqual(code, 0)
        self.assertIn("0 error(s)", out)

    def test_no_info(self):
        code, out, _ = run(["check", str(self.bad), "--no-info"])
        self.assertNotIn("hardening-missing", out)

    def test_fail_on_never(self):
        code, _, _ = run(["check", str(self.bad), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_directory_scan(self):
        code, out, _ = run(["check", self.tmp.name, "--json"])
        payload = json.loads(out)
        self.assertEqual(len(payload["units"]), 2)

    def test_rules(self):
        code, out, _ = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("runs-as-root", out)
        self.assertIn("fix:", out)

    def test_rules_json(self):
        code, out, _ = run(["rules", "--json"])
        self.assertEqual(json.loads(out)[0]["code"], "parse-error")

    def test_explain(self):
        code, out, _ = run(["explain", str(self.good), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["user"], "api")
        self.assertGreater(payload["hardening_score"], 0)
        self.assertIn("ProtectSystem", payload["present"])

    def test_explain_human(self):
        code, out, _ = run(["explain", str(self.bad)])
        self.assertIn("hardening score", out)
        self.assertIn("missing", out)

    def test_parse_error_exits_two(self):
        broken = Path(self.tmp.name) / "broken.service"
        broken.write_text("[Service\nUser=app\n", encoding="utf-8")
        code, _, err = run(["explain", str(broken)])
        self.assertEqual(code, 2)
        self.assertIn("parse error", err)

    def test_check_parse_error_is_a_finding(self):
        broken = Path(self.tmp.name) / "broken2.service"
        broken.write_text("User=app\n", encoding="utf-8")
        code, out, _ = run(["check", str(broken), "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["units"][0]["findings"][0]["rule"], "parse-error")

    def test_missing_file(self):
        with self.assertRaises(SystemExit):
            run(["check", str(Path(self.tmp.name) / "nope.service")])


if __name__ == "__main__":
    unittest.main()
