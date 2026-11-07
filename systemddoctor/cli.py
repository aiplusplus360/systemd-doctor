"""``systemd-doctor`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .core import (HARDENING_DIRECTIVES, RULES, SEVERITIES, Finding, gate, hardening_score,
                   lint, parse_unit, summarise)
from .core import UnitError

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="systemd-doctor",
        description="Audit systemd units for root execution, crash loops, and missing sandboxes.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="lint unit files")
    check.add_argument("paths", nargs="*", help="unit files or directories; '-' for stdin")
    check.add_argument("--fail-on", default="error", choices=list(SEVERITIES) + ["never"])
    check.add_argument("--json", action="store_true")
    check.add_argument("--no-info", action="store_true")

    rules = sub.add_parser("rules", help="list every rule and its remediation")
    rules.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="show the hardening score breakdown")
    explain.add_argument("path")
    explain.add_argument("--json", action="store_true")
    return parser


def _expand(paths: Sequence[str]) -> List[str]:
    if not paths:
        return ["-"]
    files: List[str] = []
    for path in paths:
        candidate = Path(path)
        if candidate.is_dir():
            for child in sorted(candidate.rglob("*")):
                if child.is_file() and child.suffix in (".service", ".socket", ".timer",
                                                       ".target", ".mount", ".conf"):
                    files.append(str(child))
        else:
            files.append(path)
    return files


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))


def _format(finding: Finding, source: str) -> str:
    where = ""
    if finding.section:
        where = " [%s]%s" % (finding.section, ("." + finding.key) if finding.key else "")
    return "%s: %s%s %s\n    %s" % (source, finding.severity.upper(),
                                    " [" + finding.rule + "]", where, finding.message)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        payload = [rule.as_dict() for rule in RULES]
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for rule in RULES:
                print("%-32s %-8s %s" % (rule.code, rule.severity, rule.summary))
                print("%-41s fix: %s" % ("", rule.remediation))
        return 0

    if args.command == "explain":
        text = _read(args.path)
        try:
            unit = parse_unit(text, Path(args.path).name)
        except UnitError as exc:
            print("%s: parse error: %s" % (args.path, exc), file=sys.stderr)
            return 2
        present = [key for key in HARDENING_DIRECTIVES if unit.has("Service", key)]
        absent = [key for key in HARDENING_DIRECTIVES if not unit.has("Service", key)]
        score = hardening_score(unit)
        payload = {
            "source": args.path,
            "user": unit.get("Service", "User") or "root",
            "type": unit.unit_type(),
            "restart": unit.restart_policy(),
            "hardening_score": score,
            "present": present,
            "absent": absent,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("user            %s" % payload["user"])
            print("type            %s" % payload["type"])
            print("restart         %s" % payload["restart"])
            print("hardening score %d%%" % score)
            print("set             %s" % (", ".join(present) or "-"))
            print("missing         %s" % (", ".join(absent) or "-"))
        return 0

    all_findings: List[Finding] = []
    report: List[Dict[str, Any]] = []
    for source in _expand(args.paths):
        text = _read(source)
        if not text.strip():
            continue
        unit, findings = lint(text, Path(source).name if source != "-" else "stdin")
        if args.no_info:
            findings = [finding for finding in findings if finding.severity != "info"]
        all_findings.extend(findings)
        report.append({
            "source": source,
            "hardening_score": hardening_score(unit),
            "summary": summarise(findings),
            "findings": [dict(finding.as_dict(), source=source) for finding in findings],
        })
        if not args.json:
            for finding in findings:
                print(_format(finding, source))

    summary = summarise(all_findings)
    if args.json:
        print(json.dumps({"summary": summary, "units": report}, indent=2))
    else:
        print("\n%d error(s), %d warning(s), %d info(s) across %d unit(s)" % (
            summary["errors"], summary["warnings"], summary["infos"], len(report)))
    return 1 if gate(all_findings, args.fail_on) else 0
