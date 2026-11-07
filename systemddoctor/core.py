"""Find the unit that runs as root with no sandbox and restarts forever.

A systemd unit is a config file with no schema and no validator, so the dangerous
defaults are invisible:

* no ``User=`` means **root**,
* no ``Restart=`` handling means a crash loop fires every 100 ms,
* no ``ProtectSystem=`` means the service can write to ``/usr``,
* ``StandardOutput=null`` means you learn about all of it from a customer.

    >>> unit = parse_unit('''
    ... [Unit]
    ... Description=api
    ... [Service]
    ... ExecStart=/opt/api/bin/serve
    ... Restart=always
    ... [Install]
    ... WantedBy=multi-user.target
    ... ''')
    >>> sorted(finding.rule for finding in lint_unit(unit))[:4]
    ['capabilities-unbounded', 'hardening-missing', 'no-documentation', 'no-new-privileges']

Hardening is scored rather than implied:

    >>> hardening_score(unit) < 40
    True
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "Finding",
    "Rule",
    "Unit",
    "UnitError",
    "SEVERITIES",
    "RULES",
    "HARDENING_DIRECTIVES",
    "parse_unit",
    "lint_unit",
    "lint",
    "summarise",
    "gate",
    "hardening_score",
    "SEVERITY_ORDER",
]

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
SEVERITIES = tuple(SEVERITY_ORDER)

HARDENING_DIRECTIVES: Tuple[str, ...] = (
    "NoNewPrivileges",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectSystem",
    "ProtectHome",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "RestrictAddressFamilies",
    "RestrictNamespaces",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "SystemCallFilter",
    "SystemCallArchitectures",
    "CapabilityBoundingSet",
    "UMask",
)

_SAFE_TRUE = {"1", "yes", "true", "on"}
_SANDBOX_KEYS = ("ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
                 "NoNewPrivileges")


class UnitError(ValueError):
    """Raised when a unit file cannot be parsed."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__("%s (line %d)" % (message, line))
        self.message = message
        self.line = line


class Finding:
    """One rule violation."""

    __slots__ = ("rule", "severity", "section", "key", "message")

    def __init__(self, rule: str, severity: str, message: str,
                 section: str = "", key: str = "") -> None:
        self.rule = rule
        self.severity = severity
        self.section = section
        self.key = key
        self.message = message

    def as_dict(self) -> Dict[str, str]:
        return {"rule": self.rule, "severity": self.severity, "section": self.section,
                "key": self.key, "message": self.message}

    def __repr__(self) -> str:
        return "Finding(%s, %s, %s.%s)" % (self.severity, self.rule, self.section, self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (self.rule, self.section, self.key) == (other.rule, other.section, other.key)

    def __hash__(self) -> int:
        return hash((self.rule, self.section, self.key))


class Rule:
    __slots__ = ("code", "severity", "summary", "remediation")

    def __init__(self, code: str, severity: str, summary: str, remediation: str) -> None:
        self.code = code
        self.severity = severity
        self.summary = summary
        self.remediation = remediation

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "severity": self.severity, "summary": self.summary,
                "remediation": self.remediation}


RULES: Tuple[Rule, ...] = (
    Rule("parse-error", "error", "unit file is not a valid INI-style unit",
         "every directive must be KEY=VALUE inside a [Section]"),
    Rule("runs-as-root", "error", "service has no User= and will run as root",
         "set User= and Group= to a dedicated account"),
    Rule("oneshot-restart", "error", "Type=oneshot combined with Restart= is ignored",
         "use Restart=no for oneshot units, or switch to Type=exec"),
    Rule("restart-loop", "error", "unbounded Restart= can hammer the host forever",
         "set StartLimitIntervalSec= and StartLimitBurst=, and RestartSec>=1"),
    Rule("relative-exec", "error", "ExecStart must be an absolute path",
         "use /usr/local/bin/... rather than a bare command name"),
    Rule("no-sandbox", "warning", "service has no filesystem or privilege sandbox",
         "set ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes"),
    Rule("no-new-privileges", "warning", "NoNewPrivileges is not enabled",
         "set NoNewPrivileges=yes"),
    Rule("writable-system", "warning", "ProtectSystem does not make /usr read-only",
         "set ProtectSystem=strict and list writable paths in ReadWritePaths="),
    Rule("missing-install", "warning", "no [Install] section, so the unit cannot be enabled",
         "add WantedBy=multi-user.target"),
    Rule("network-online-without-wants", "warning",
         "After=network-online.target without Wants= does not wait for the network",
         "add Wants=network-online.target"),
    Rule("kill-mode-none", "warning", "KillMode=none leaves orphan processes after stop",
         "use KillMode=control-group (the default) or mixed"),
    Rule("null-output", "warning", "StandardOutput=null discards the only diagnostic trail",
         "use journal or syslog"),
    Rule("low-nofile", "warning", "LimitNOFILE is below the usual file-descriptor need",
         "set LimitNOFILE=65536 for network services"),
    Rule("capabilities-unbounded", "warning", "root service keeps the full capability set",
         "set CapabilityBoundingSet= to the capabilities actually used"),
    Rule("no-documentation", "info", "no Documentation= link",
         "point at the runbook"),
    Rule("hardening-missing", "info", "several cheap hardening directives are absent",
         "see `systemd-doctor rules` and add them incrementally"),
    Rule("exec-with-shell", "info", "ExecStart uses a shell, so stop codes are the shell's",
         "call the binary directly and let systemd manage the process"),
)


class Unit:
    """A parsed unit file: sections, directives, and repeated directives."""

    def __init__(self, name: str = "unit.service") -> None:
        self.name = name
        self.sections: Dict[str, Dict[str, List[str]]] = {}
        self.order: List[str] = []

    def add(self, section: str, key: str, value: str) -> None:
        if section not in self.sections:
            self.sections[section] = {}
            self.order.append(section)
        self.sections[section].setdefault(key, []).append(value)

    def get(self, section: str, key: str, default: Optional[str] = None) -> Optional[str]:
        values = self.sections.get(section, {}).get(key)
        return values[-1] if values else default

    def all(self, section: str, key: str) -> List[str]:
        return list(self.sections.get(section, {}).get(key, ()))

    def has(self, section: str, key: str) -> bool:
        return key in self.sections.get(section, {})

    @property
    def service(self) -> Mapping[str, List[str]]:
        return self.sections.get("Service", {})

    def exec_starts(self) -> List[str]:
        return self.all("Service", "ExecStart")

    def restart_policy(self) -> str:
        return (self.get("Service", "Restart") or "no").strip().lower()

    def unit_type(self) -> str:
        return (self.get("Service", "Type") or "simple").strip().lower()

    def is_root(self) -> bool:
        user = self.get("Service", "User")
        return user is None or user.strip() in ("", "root", "0")

    def sandbox_directives(self) -> Dict[str, str]:
        found = {}
        for key in _SANDBOX_KEYS:
            value = self.get("Service", key)
            if value is not None:
                found[key] = value.strip()
        return found

    def __repr__(self) -> str:
        return "Unit(%r, sections=%s)" % (self.name, self.order)


def parse_unit(text: str, name: str = "unit.service") -> Unit:
    """Parse INI-style unit syntax, including ``\\`` continuation lines.

    >>> unit = parse_unit("[Service]\\nUser=app\\nExecStart=/usr/bin/api --flag\\n")
    >>> unit.get("Service", "User")
    'app'
    >>> try:
    ...     parse_unit("User=app\\n")
    ... except UnitError as err:
    ...     print(err)
    directive outside any section (line 1)
    """
    unit = Unit(name)
    section: Optional[str] = None
    pending = ""
    pending_line = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not pending:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
        if line.endswith("\\"):
            if not pending:
                pending_line = number
            pending += line[:-1].rstrip() + " "
            continue
        if pending:
            line = pending + line.strip()
            number_used = pending_line
            pending = ""
        else:
            number_used = number
        stripped = line.strip()
        if stripped.startswith("["):
            if not stripped.endswith("]"):
                raise UnitError("section header is not closed", number_used)
            section = stripped[1:-1].strip()
            if not section:
                raise UnitError("empty section name", number_used)
            if section not in unit.sections:
                unit.sections[section] = {}
                unit.order.append(section)
            continue
        if section is None:
            raise UnitError("directive outside any section", number_used)
        key, separator, value = stripped.partition("=")
        if not separator:
            raise UnitError("expected KEY=VALUE", number_used)
        key = key.strip()
        if not key:
            raise UnitError("empty directive name", number_used)
        unit.add(section, key, value.strip())
    if pending:
        raise UnitError("file ends with a continuation", pending_line)
    return unit


def _exec_path(value: str) -> str:
    """Strip systemd's ExecStart prefix characters (``-@+!:``)."""
    return value.lstrip("-@+!:").strip()


def _is_true(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() in _SAFE_TRUE


def hardening_score(unit: Unit) -> int:
    """Percentage of :data:`HARDENING_DIRECTIVES` explicitly set.

    Zero means nothing is sandboxed; 100 means every directive is present. The
    point is not the number but the trend when you add one directive at a time.

    >>> hardening_score(parse_unit("[Service]\\nUser=app\\n"))
    0
    >>> hardening_score(parse_unit("[Service]\\n" + "".join(
    ...     key + "=yes\\n" for key in HARDENING_DIRECTIVES)))
    100
    """
    present = sum(1 for key in HARDENING_DIRECTIVES if unit.has("Service", key))
    return int(round(100.0 * present / len(HARDENING_DIRECTIVES)))


def lint_unit(unit: Unit) -> List[Finding]:
    """Rules for one unit. Ordering puts errors first.

    >>> lint_unit(parse_unit("[Service]\\nUser=app\\nExecStart=/bin/true\\n"))[0].severity
    'warning'
    """
    findings: List[Finding] = []
    service = unit.sections.get("Service")
    if service is None:
        findings.append(Finding("parse-error", "error",
                                "unit has no [Service] section"))
        return findings

    if unit.is_root():
        findings.append(Finding("runs-as-root", "error",
                                "no User= is set, so systemd runs this as root",
                                "Service", "User"))

    for value in unit.exec_starts():
        path = _exec_path(value)
        if path and not path.startswith("/"):
            findings.append(Finding("relative-exec", "error",
                                    "ExecStart %r is not an absolute path" % path,
                                    "Service", "ExecStart"))
        command = path.split()[0] if path.split() else ""
        if command.endswith(("/sh", "/bash", "/zsh")):
            findings.append(Finding("exec-with-shell", "info",
                                    "ExecStart invokes a shell; exit status belongs to it",
                                    "Service", "ExecStart"))

    policy = unit.restart_policy()
    if policy in ("always", "on-failure") and unit.unit_type() == "oneshot":
        findings.append(Finding("oneshot-restart", "error",
                                "Type=oneshot with Restart=%s is ignored by systemd" % policy,
                                "Service", "Restart"))
    if policy in ("always", "on-failure"):
        burst = unit.get("Service", "StartLimitBurst")
        interval = (unit.get("Unit", "StartLimitIntervalSec")
                    or unit.get("Service", "StartLimitIntervalSec"))
        restart_sec = unit.get("Service", "RestartSec")
        too_fast = False
        if restart_sec is not None:
            try:
                too_fast = float(restart_sec.rstrip("s")) < 1.0
            except ValueError:
                too_fast = False
        if burst is None or interval is None or too_fast:
            findings.append(Finding(
                "restart-loop", "error",
                "Restart=%s without a start limit%s can loop forever" % (
                    policy, " or with RestartSec<1" if too_fast else ""),
                "Service", "Restart"))

    if not unit.sandbox_directives():
        findings.append(Finding("no-sandbox", "warning",
                                "none of ProtectSystem, ProtectHome, PrivateTmp, "
                                "PrivateDevices, NoNewPrivileges is set", "Service"))

    if not _is_true(unit.get("Service", "NoNewPrivileges")):
        findings.append(Finding("no-new-privileges", "warning",
                                "NoNewPrivileges is not enabled",
                                "Service", "NoNewPrivileges"))

    protect_system = (unit.get("Service", "ProtectSystem") or "").strip().lower()
    if protect_system not in ("strict", "full"):
        findings.append(Finding("writable-system", "warning",
                                "ProtectSystem is %r; /etc stays writable" % (
                                    protect_system or "unset"),
                                "Service", "ProtectSystem"))

    if unit.get("Install", "WantedBy") is None and unit.get("Install", "RequiredBy") is None:
        findings.append(Finding("missing-install", "warning",
                                "no WantedBy= or RequiredBy= in [Install]",
                                "Install", "WantedBy"))

    after = " ".join(unit.all("Unit", "After")).split()
    wants = " ".join(unit.all("Unit", "Wants") + unit.all("Unit", "Requires")).split()
    if "network-online.target" in after and "network-online.target" not in wants:
        findings.append(Finding("network-online-without-wants", "warning",
                                "After=network-online.target has no matching Wants=",
                                "Unit", "After"))

    if (unit.get("Service", "KillMode") or "").strip().lower() == "none":
        findings.append(Finding("kill-mode-none", "warning",
                                "KillMode=none leaves children running after stop",
                                "Service", "KillMode"))

    for key in ("StandardOutput", "StandardError"):
        if (unit.get("Service", key) or "").strip().lower() == "null":
            findings.append(Finding("null-output", "warning",
                                    "%s=null discards logs" % key, "Service", key))

    nofile = unit.get("Service", "LimitNOFILE")
    if nofile is not None:
        try:
            if int(nofile) < 4096:
                findings.append(Finding("low-nofile", "warning",
                                        "LimitNOFILE=%s is low for a network service" % nofile,
                                        "Service", "LimitNOFILE"))
        except ValueError:
            pass

    if unit.is_root() and not unit.has("Service", "CapabilityBoundingSet"):
        findings.append(Finding("capabilities-unbounded", "warning",
                                "root service keeps every capability", "Service",
                                "CapabilityBoundingSet"))

    if not unit.has("Unit", "Documentation"):
        findings.append(Finding("no-documentation", "info",
                                "no Documentation= link", "Unit", "Documentation"))

    missing = [key for key in HARDENING_DIRECTIVES if not unit.has("Service", key)]
    if len(missing) > len(HARDENING_DIRECTIVES) // 2:
        findings.append(Finding("hardening-missing", "info",
                                "%d hardening directives absent (score %d%%)" % (
                                    len(missing), hardening_score(unit)), "Service"))

    findings.sort(key=lambda finding: (-SEVERITY_ORDER.get(finding.severity, 0),
                                       finding.rule))
    return findings


def lint(text: str, name: str = "unit.service") -> Tuple[Unit, List[Finding]]:
    """Parse and lint in one call. Parse failures come back as a finding.

    >>> unit, findings = lint("[Service]\\nUser=app\\nExecStart=/bin/true\\n"
    ...                       "ProtectSystem=strict\\nProtectHome=yes\\n"
    ...                       "PrivateTmp=yes\\nNoNewPrivileges=yes\\n"
    ...                       "[Install]\\nWantedBy=multi-user.target\\n")
    >>> findings[0].rule
    'hardening-missing'
    """
    try:
        unit = parse_unit(text, name)
    except UnitError as exc:
        return Unit(name), [Finding("parse-error", "error", str(exc))]
    return unit, lint_unit(unit)


def summarise(findings: Sequence[Finding]) -> Dict[str, Any]:
    """Counts by severity plus a ``clean`` flag that ignores info-level rules.

    >>> summarise([])["clean"]
    True
    """
    counts = {severity: 0 for severity in SEVERITIES}
    by_rule: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
    return {
        "total": len(findings),
        "errors": counts["error"],
        "warnings": counts["warning"],
        "infos": counts["info"],
        "by_rule": dict(sorted(by_rule.items())),
        "clean": not any(f.severity in ("error", "warning") for f in findings),
    }


def gate(findings: Sequence[Finding], fail_on: str = "error") -> bool:
    """``True`` when the run should fail.

    >>> gate([Finding("x", "info", "m")], "error")
    False
    >>> gate([Finding("x", "warning", "m")], "warning")
    True
    """
    if fail_on == "never":
        return False
    if fail_on not in SEVERITY_ORDER:
        raise ValueError("fail_on must be one of %s or 'never'" % (SEVERITIES,))
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold for finding in findings)
