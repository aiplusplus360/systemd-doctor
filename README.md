# systemd-doctor

Find the unit that runs as root with no sandbox and restarts forever.

```console
$ systemd-doctor check /etc/systemd/system/api.service
/etc/systemd/system/api.service: ERROR [runs-as-root] [Service].User
    no User= is set, so systemd runs this as root
/etc/systemd/system/api.service: ERROR [restart-loop] [Service].Restart
    Restart=always without a start limit or with RestartSec<1 can loop forever
/etc/systemd/system/api.service: WARNING [no-sandbox] [Service]
    none of ProtectSystem, ProtectHome, PrivateTmp, PrivateDevices, NoNewPrivileges is set
/etc/systemd/system/api.service: WARNING [writable-system] [Service].ProtectSystem
    ProtectSystem is 'unset'; /etc stays writable
/etc/systemd/system/api.service: WARNING [null-output] [Service].StandardOutput
    StandardOutput=null discards logs

1 error(s), 4 warning(s), 2 info(s) across 1 unit(s)
```

## Why this exists

There is no `systemd-lint` in the base image, and the two directives that matter
most are the ones that are *absent*. A unit with no `User=` runs as root; a unit
with `Restart=always` and no `StartLimitBurst=` restarts forever; a unit with
`StandardOutput=null` deletes the evidence.

`systemd-doctor` reads units as files — no `systemctl`, no root, no running
system — so it works in CI, in a pre-commit hook, and on a laptop reviewing a
bundle from a build.

```console
$ systemd-doctor explain api.service
user            root
type            simple
restart         always
hardening score 10%
set             NoNewPrivileges
missing         PrivateTmp, PrivateDevices, ProtectSystem, ProtectHome, ...
```

## Install

```console
git clone https://github.com/aiplusplus360/systemd-doctor
cd systemd-doctor
python -m pip install -e .
```

Python 3.9+. Zero dependencies.

## CLI

```console
systemd-doctor check /etc/systemd/system/            # recurse over unit suffixes
systemd-doctor check a.service b.timer -             # explicit files, or stdin
systemd-doctor check units/ --json                   # machine-readable
systemd-doctor check units/ --fail-on warning        # stricter gate
systemd-doctor check units/ --no-info                # drop informational findings
systemd-doctor explain api.service [--json]          # hardening breakdown
systemd-doctor rules [--json]                        # every rule and its fix
```

Exit codes: `0` clean at the requested severity, `1` findings at or above
`--fail-on`, `2` unreadable file. `check` also reports parse errors as a finding
instead of crashing, so one broken unit does not hide the other nineteen.

## JSON output

```json
{
  "summary": { "total": 5, "errors": 1, "warnings": 3, "infos": 1,
               "by_rule": { "null-output": 1, "no-sandbox": 1, "restart-loop": 1,
                            "runs-as-root": 1, "writable-system": 1 },
               "clean": false },
  "units": [
    { "source": "api.service", "hardening_score": 10,
      "summary": { "...": "..." },
      "findings": [
        { "rule": "runs-as-root", "severity": "error", "section": "Service",
          "key": "User", "message": "no User= is set...", "source": "api.service" }
      ] }
  ]
}
```

## Rules

| Rule | Severity | What it catches |
| --- | --- | --- |
| `runs-as-root` | error | no `User=`, or `root`/`0` |
| `oneshot-restart` | error | `Type=oneshot` with `Restart=` |
| `restart-loop` | error | `Restart=` without a start limit, or `RestartSec<1` |
| `relative-exec` | error | `ExecStart` not an absolute path |
| `no-sandbox` | warning | no `Protect*`, `PrivateTmp`, or `NoNewPrivileges` |
| `no-new-privileges` | warning | `NoNewPrivileges` not enabled |
| `writable-system` | warning | `ProtectSystem` not `strict`/`full` |
| `missing-install` | warning | no `WantedBy=`/`RequiredBy=` |
| `network-online-without-wants` | warning | `After=` without `Wants=` |
| `kill-mode-none` | warning | `KillMode=none` |
| `null-output` | warning | `StandardOutput`/`StandardError` = `null` |
| `low-nofile` | warning | `LimitNOFILE` below 4096 |
| `capabilities-unbounded` | warning | root service with no `CapabilityBoundingSet` |
| `no-documentation` | info | no `Documentation=` link |
| `hardening-missing` | info | more than half the hardening directives absent |
| `exec-with-shell` | info | `ExecStart` is a shell |

## The hardening score

Twenty directives are counted; the score is the percentage present.

\[
\text{score} = 100 \times \frac{\lvert \text{present} \rvert}{\lvert \text{hardening directives} \rvert}
\]

It is a progress metric, not a security guarantee: `ProtectSystem=strict` with
`ReadWritePaths=/` is present and useless. Use it to see the trend as you add one
directive per deploy, and use `check` for the rules that actually block.

```
user            api
type            exec
restart         on-failure
hardening score 85%
set             NoNewPrivileges, PrivateTmp, ProtectSystem, ProtectHome, ...
missing         ProtectClock, ProtectHostname, RestrictNamespaces, ...
```

## Parsing

Units are INI files with quirks this handles:

- `\` line continuations (and rejecting a file that ends mid-continuation),
- `#` and `;` comments, including full-line comments inside continuations,
- repeated directives (`ExecStart=`, `After=`, `Environment=`) preserved in order,
  with `get()` returning the last value as systemd does,
- directives before any `[Section]` rejected with a line number,
- empty values (`Environment=`) preserved rather than dropped.

## Library

```python
from systemddoctor import parse_unit, lint_unit, hardening_score, gate

unit = parse_unit(open("api.service").read(), "api.service")
findings = lint_unit(unit)
if gate(findings, "warning"):
    raise SystemExit("unit is not safe to deploy")
print(hardening_score(unit))
```

## Testing

```console
python -m unittest discover -s tests -v   # 57 tests
python -m doctest systemddoctor/core.py
```

The tests cover continuation joining, repeated directives, every rule's trigger
and its clean counterpart, score proportionality, and the CLI contract including
directories, stdin, `--fail-on`, and parse-error reporting.

## License

MIT.
