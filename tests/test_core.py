import unittest

from systemddoctor import (HARDENING_DIRECTIVES, RULES, gate, hardening_score, lint,
                           lint_unit, parse_unit, summarise)
from systemddoctor.core import UnitError


HARDENED = """[Unit]
Description=api
Documentation=https://runbooks.example/api
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=api
Group=api
ExecStart=/opt/api/bin/serve --port 8080
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=60
StartLimitBurst=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077
StandardOutput=journal

[Install]
WantedBy=multi-user.target
"""


class ParseTests(unittest.TestCase):
    def test_sections_and_values(self):
        unit = parse_unit("[Unit]\nDescription=a b\n[Service]\nUser=app\n")
        self.assertEqual(unit.order, ["Unit", "Service"])
        self.assertEqual(unit.get("Unit", "Description"), "a b")

    def test_repeated_directives_are_kept(self):
        unit = parse_unit("[Unit]\nAfter=a.service\nAfter=b.service\n")
        self.assertEqual(unit.all("Unit", "After"), ["a.service", "b.service"])

    def test_last_value_wins(self):
        unit = parse_unit("[Service]\nUser=a\nUser=b\n")
        self.assertEqual(unit.get("Service", "User"), "b")

    def test_comments_and_blank_lines(self):
        unit = parse_unit("# comment\n\n[Service]\n; also comment\nUser=app\n")
        self.assertEqual(unit.get("Service", "User"), "app")

    def test_continuation_lines(self):
        unit = parse_unit("[Service]\nExecStart=/bin/sh -c \\\n  'echo hi'\n")
        self.assertEqual(unit.get("Service", "ExecStart"), "/bin/sh -c 'echo hi'")

    def test_directive_before_section_rejected(self):
        with self.assertRaises(UnitError) as ctx:
            parse_unit("User=app\n")
        self.assertEqual(ctx.exception.line, 1)

    def test_missing_equals_rejected(self):
        with self.assertRaises(UnitError):
            parse_unit("[Service]\nUser app\n")

    def test_empty_section_rejected(self):
        with self.assertRaises(UnitError):
            parse_unit("[]\n")

    def test_unclosed_section_rejected(self):
        with self.assertRaises(UnitError):
            parse_unit("[Service\n")

    def test_trailing_continuation_rejected(self):
        with self.assertRaises(UnitError):
            parse_unit("[Service]\nExecStart=/bin/true \\\n")

    def test_value_may_be_empty(self):
        unit = parse_unit("[Service]\nEnvironment=\n")
        self.assertEqual(unit.get("Service", "Environment"), "")


class RootTests(unittest.TestCase):
    def test_missing_user_is_root(self):
        self.assertTrue(parse_unit("[Service]\nExecStart=/bin/true\n").is_root())

    def test_explicit_root(self):
        self.assertTrue(parse_unit("[Service]\nUser=root\n").is_root())

    def test_uid_zero(self):
        self.assertTrue(parse_unit("[Service]\nUser=0\n").is_root())

    def test_named_user_is_not_root(self):
        self.assertFalse(parse_unit("[Service]\nUser=api\n").is_root())


class RuleTests(unittest.TestCase):
    def test_hardened_unit_has_no_errors(self):
        _, findings = lint(HARDENED)
        self.assertEqual([f for f in findings if f.severity in ("error", "warning")], [])

    def test_root_service_is_error(self):
        unit = parse_unit("[Service]\nExecStart=/bin/true\n")
        self.assertIn("runs-as-root", [finding.rule for finding in lint_unit(unit)])

    def test_relative_exec(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=api serve\n")
        self.assertIn("relative-exec", [finding.rule for finding in lint_unit(unit)])

    def test_exec_prefix_characters_are_ignored(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=-/usr/bin/true\n")
        self.assertNotIn("relative-exec", [finding.rule for finding in lint_unit(unit)])

    def test_oneshot_with_restart(self):
        text = ("[Service]\nType=oneshot\nUser=app\nExecStart=/usr/bin/true\n"
                "Restart=always\n[Install]\nWantedBy=multi-user.target\n")
        unit = parse_unit(text)
        self.assertIn("oneshot-restart", [finding.rule for finding in lint_unit(unit)])

    def test_unbounded_restart(self):
        text = ("[Service]\nUser=app\nExecStart=/usr/bin/true\nRestart=always\n"
                "[Install]\nWantedBy=multi-user.target\n")
        unit = parse_unit(text)
        self.assertIn("restart-loop", [finding.rule for finding in lint_unit(unit)])

    def test_bounded_restart_is_clean(self):
        text = ("[Service]\nUser=app\nExecStart=/usr/bin/true\nRestart=always\nRestartSec=5\n"
                "StartLimitIntervalSec=60\nStartLimitBurst=3\n"
                "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
                "NoNewPrivileges=yes\n[Install]\nWantedBy=multi-user.target\n")
        rules = [finding.rule for finding in lint_unit(parse_unit(text))]
        self.assertNotIn("restart-loop", rules)
        self.assertNotIn("no-sandbox", rules)

    def test_fast_restart_sec_is_a_loop(self):
        text = ("[Service]\nUser=app\nExecStart=/usr/bin/true\nRestart=on-failure\n"
                "RestartSec=0.2\nStartLimitIntervalSec=60\nStartLimitBurst=3\n")
        self.assertIn("restart-loop", [finding.rule for finding in lint_unit(parse_unit(text))])

    def test_no_sandbox(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\n")
        self.assertIn("no-sandbox", [finding.rule for finding in lint_unit(unit)])

    def test_writable_system(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\n"
                          "ProtectSystem=yes\nPrivateTmp=yes\n")
        rules = [finding.rule for finding in lint_unit(unit)]
        self.assertIn("writable-system", rules)
        self.assertNotIn("no-sandbox", rules)

    def test_protect_system_full_is_accepted(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\n"
                          "ProtectSystem=full\nPrivateTmp=yes\n")
        self.assertNotIn("writable-system",
                         [finding.rule for finding in lint_unit(unit)])

    def test_missing_install(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\n"
                          "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
                          "NoNewPrivileges=yes\n")
        self.assertIn("missing-install", [finding.rule for finding in lint_unit(unit)])

    def test_network_online_without_wants(self):
        unit = parse_unit("[Unit]\nAfter=network-online.target\n[Service]\nUser=app\n"
                          "ExecStart=/usr/bin/true\n")
        self.assertIn("network-online-without-wants",
                      [finding.rule for finding in lint_unit(unit)])

    def test_kill_mode_none(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\nKillMode=none\n")
        self.assertIn("kill-mode-none", [finding.rule for finding in lint_unit(unit)])

    def test_null_output(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\nStandardOutput=null\n")
        self.assertIn("null-output", [finding.rule for finding in lint_unit(unit)])

    def test_low_nofile(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\nLimitNOFILE=1024\n")
        self.assertIn("low-nofile", [finding.rule for finding in lint_unit(unit)])

    def test_high_nofile_is_fine(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/usr/bin/true\nLimitNOFILE=65536\n")
        self.assertNotIn("low-nofile", [finding.rule for finding in lint_unit(unit)])

    def test_shell_exec_is_info(self):
        unit = parse_unit("[Service]\nUser=app\nExecStart=/bin/bash -c 'serve'\n")
        self.assertIn("exec-with-shell", [finding.rule for finding in lint_unit(unit)])

    def test_no_service_section(self):
        _, findings = lint("[Unit]\nDescription=x\n")
        self.assertEqual(findings[0].rule, "parse-error")

    def test_parse_error_comes_back_as_finding(self):
        _, findings = lint("User=app\n")
        self.assertEqual(findings[0].severity, "error")

    def test_errors_sort_before_warnings(self):
        _, findings = lint("[Service]\nExecStart=/bin/true\n")
        severities = [finding.severity for finding in findings]
        self.assertEqual(severities[0], "error")
        self.assertEqual(severities[-1], "info")

    def test_rules_registry_matches_findings(self):
        codes = {rule.code for rule in RULES}
        _, findings = lint("[Service]\nExecStart=/bin/true\n")
        self.assertTrue({finding.rule for finding in findings} <= codes)


class ScoreTests(unittest.TestCase):
    def test_empty_unit_scores_zero(self):
        self.assertEqual(hardening_score(parse_unit("[Service]\nUser=app\n")), 0)

    def test_full_unit_scores_hundred(self):
        text = "[Service]\n" + "".join(key + "=yes\n" for key in HARDENING_DIRECTIVES)
        self.assertEqual(hardening_score(parse_unit(text)), 100)

    def test_score_is_proportional(self):
        text = "[Service]\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
        expected = round(200.0 / len(HARDENING_DIRECTIVES))
        self.assertEqual(hardening_score(parse_unit(text)), expected)

    def test_hardened_unit_scores_high(self):
        self.assertGreaterEqual(hardening_score(parse_unit(HARDENED)), 90)


class ReportTests(unittest.TestCase):
    def test_summarise(self):
        summary = summarise(lint("[Service]\nExecStart=/bin/true\n")[1])
        self.assertGreaterEqual(summary["errors"], 1)
        self.assertFalse(summary["clean"])

    def test_gate(self):
        findings = lint("[Service]\nExecStart=/bin/true\n")[1]
        self.assertTrue(gate(findings, "error"))
        self.assertFalse(gate(findings, "never"))

    def test_gate_rejects_unknown(self):
        with self.assertRaises(ValueError):
            gate([], "fatal")


if __name__ == "__main__":
    unittest.main()
