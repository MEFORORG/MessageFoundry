# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run ``pip-audit`` over a hashed lock so it audits every pin, whatever the pin's marker.

ONE IMPLEMENTATION, TWO CALLERS. It ships in the wheel, stdlib only, so an adopter's CI can run the
code the engine's own gate runs: ``python -P -m messagefoundry.security.audit_all_platforms <lock>``.
The engine's ``security.yml`` reaches it through ``scripts/security/audit_all_platforms.py``, a thin
wrapper that needs no engine install; the ``audit-pin`` job ``messagefoundry init`` generates calls
the module when the adopter commits a hashed ``requirements.lock`` (``messagefoundry/scaffold.py``).

THE GAP THIS CLOSES. ``pip-audit -r <lock>`` evaluates each requirement's environment marker against
the HOST it runs on and silently skips a requirement whose marker does not match. Both of its
collection paths do it: through pip (pip honours the marker) and with ``--disable-pip``
(``RequirementSource._collect_preresolved_deps`` in pip-audit 2.10.1 calls ``marker.evaluate()`` and
``continue``s). Measured 2026-10-17 on Windows with pip-audit from ``ci/locks/ci-scanners.lock``:
``urllib3==1.26.0`` with no marker reports its PYSEC ids, ``; sys_platform == 'linux'`` reports
"No known vulnerabilities found", and ``; sys_platform == 'win32'`` reports the same ids as no
marker. (How many ids depends on the advisory database on the day: three when first measured, twelve
when re-measured later that day.) The
required audit runs on ``ubuntu-latest``, so that gate never audited a pin gated to Windows: at
least ``sys_platform == 'win32'`` (sspilib, colorama) and ``os_name == 'nt'`` (colorama in
``release-tools.lock``). Dependabot's alerts read ``uv.lock`` separately and are not this gate. The
owner ruled on 2026-10-16 that Windows is the only supported v1 deployment platform, so the pins the
gate skipped were Windows-only pins of the platform that ships. The unmarked bulk of each lock was
always audited.

WHAT IT DOES, in order, exiting with the first non-zero status:

1. ``pip install --dry-run --ignore-installed --require-hashes -r <lock>`` on the lock AS COMMITTED.
   This keeps what the old ``pip-audit -r <lock>`` did as a side effect: its pip path dry-run
   installed the lock into a fresh venv, so a pin with a wrong hash or no installable artifact on the
   runner reddened the gate. For ``ci/locks/ci-quality.lock`` that was the only such check in a
   required job. Markers are evaluated here, deliberately: this checks what the host would install.
2. Writes a copy of the lock with the ``; <marker>`` removed from every requirement line, the pins
   and ``--hash`` lines untouched, into a temporary directory (under ``$RUNNER_TEMP`` when set; never
   committed, never installed), and prints each pin it un-gated.
3. ``pip-audit -r <copy> --desc --disable-pip --strict`` plus any extra arguments (``--ignore-vuln
   <ID>`` for a triaged advisory, which therefore goes AFTER the lock).

WHY STRIPPING IS SOUND HERE. Every pin in a uv export is a version that uv resolved for some
environment. The engine sets no ``[tool.uv] environments``, so that includes environments nobody
supports (PyPy, cygwin, macOS). Auditing those pins too is accepted: an advisory against one fails
loudly and is triaged with ``--ignore-vuln``, while skipping a pin fails silently, which is the
defect above. ``--disable-pip`` is not left to the caller: without it pip-audit installs the
requirements through pip on the host, and a Windows-only distribution need not install on Linux.
With it and a hashed file, pip-audit reads the pins as already resolved and refuses any requirement
that lacks a hash. ``--strict`` makes a pin pip-audit could not look up (a release PyPI has removed,
say) fail the audit instead of being skipped.

WHAT IT REFUSES, exit 2: a lock with no requirement lines at all, so an empty input cannot read as
a clean audit; and a pip option line (``-r``, ``-c``, ``-e``, an index URL), which a uv export
never writes and which would resolve against the temporary copy's directory, or escape the strip,
rather than audit what it names (``uv export --no-emit-project`` writes none; a lock tool can
write at least an index URL, ``--trusted-host`` and ``--find-links`` lines unless told not to); and
a requirement that continues onto a line other than a hash, option or comment, where a marker
would stay in place. It does not judge whether a non-empty lock is complete; released-line-audit
carries its own floor for that.

It reads lines as pip does: a requirement or option is any line that does not continue the one
before it (a line ending in a backslash continues, unless it is a comment), indented or not. A
UTF-8, UTF-16 or UTF-32 byte-order mark is honoured, as pip honours it.

Both subprocesses start through ``messagefoundry.childenv.python_module_argv``, so with ``-P``
(the checked-out tree, the current directory, is not on their ``sys.path`` and cannot shadow a
module the auditor imports) and the engine's other child-interpreter flags.

WHAT IT DOES NOT HANDLE, stated rather than papered over. If a lock ever pins ONE name at two
versions under two markers (a resolver fork), the copy carries both and pip-audit refuses it with
"has duplicate requirements". That red is wanted: the fork needs a decision about which pins to
audit, and silently auditing one of them would recreate the gap above. No lock here forks today.
"""

from __future__ import annotations

import argparse
import codecs
import io
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from messagefoundry.childenv import hook_environment, python_module_argv


def is_requirement_line(line: str) -> bool:
    """A requirement starts at column 0 and is neither a comment nor a pip option.

    Applied to a line that starts a logical line, with its indentation removed: the ``--hash``
    lines a uv export writes under each requirement continue it, so they are never asked.
    """
    return bool(line) and not line[0].isspace() and line[0] not in "#-"


def _body(line: str) -> str:
    """``line`` without its terminator, whichever of those ``str.splitlines`` ends it on."""
    return line.splitlines()[0] if line else ""


def _kinds(lines: list[str]) -> list[str]:
    """Classify each physical line as pip joins them into logical lines.

    ``requirement`` or ``option`` where a logical line starts; ``continued`` where a requirement
    goes on to a line that is neither a hash or other option nor a comment, so a marker there would
    escape the strip; ``other`` for the rest. A line ending in a backslash continues onto the next,
    unless it is a comment.
    """
    kinds: list[str] = []
    continued = in_requirement = False
    for line in lines:
        body = _body(line)
        head = body.lstrip()
        if not continued:
            in_requirement = is_requirement_line(head)
            kind = "requirement" if in_requirement else "option" if head[:1] == "-" else "other"
        else:
            kind = "continued" if in_requirement and head[:1] not in ("", "-", "#") else "other"
        kinds.append(kind)
        continued = body.endswith("\\") and not head.startswith("#")
    return kinds


def _lines_of(text: str, kind: str) -> list[str]:
    lines = text.splitlines()
    return [ln for ln, k in zip(lines, _kinds(lines), strict=True) if k == kind]


def requirement_lines(text: str) -> list[str]:
    """The lines that start a requirement, without their indentation."""
    return [ln.lstrip() for ln in _lines_of(text, "requirement")]


def option_lines(text: str) -> list[str]:
    """The pip option lines (``-r``, ``--index-url``, ...) that start a logical line."""
    return _lines_of(text, "option")


def continued_requirement_lines(text: str) -> list[str]:
    """Lines a requirement continues onto that the strip does not rewrite (see :func:`_kinds`)."""
    return _lines_of(text, "continued")


#: Longest first: a UTF-32-LE mark begins with the UTF-16-LE one.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def read_lock(path: Path) -> str:
    """Decode a lock as pip would: by its UTF-32 or UTF-16 byte-order mark, otherwise as UTF-8."""
    raw = path.read_bytes()
    codec = next((name for bom, name in _BOMS if raw.startswith(bom)), "utf-8-sig")
    # Universal newlines, as Path.read_text gives them.
    return io.StringIO(raw.decode(codec), newline=None).read()


def strip_markers(text: str) -> tuple[str, list[str], int]:
    """Return ``(text without markers, the entries whose marker was removed, requirement count)``."""
    out: list[str] = []
    stripped: list[str] = []
    requirements = 0
    lines = text.splitlines(keepends=True)
    for line, kind in zip(lines, _kinds(lines), strict=True):
        body = _body(line)
        if kind == "requirement":
            requirements += 1
            pin, has_marker, marker = body.partition(";")
            if has_marker:
                continued = body.endswith("\\")
                pin = pin.rstrip()
                marker = marker.strip().removesuffix("\\").rstrip()
                stripped.append(f"{pin.lstrip()} ; {marker}")
                line = pin + (" \\" if continued else "") + line[len(body) :]
        out.append(line)
    return "".join(out), stripped, requirements


def _run(cmd: list[str]) -> int:
    # hook_environment: everything outside the engine's MEFOR_* namespace and its named secrets, so
    # pip and pip-audit keep the index, proxy and certificate settings they read from the
    # environment, and an engine secret set on the same runner does not reach them.
    env = hook_environment()
    return subprocess.run(cmd, check=False, env=env).returncode  # nosec B603 - fixed argv, no shell


def main(argv: Sequence[str] | None = None, run: Callable[[list[str]], int] = _run) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("lock", type=Path, help="the hashed lock to audit")
    parser.add_argument(
        "pip_audit_args",
        nargs=argparse.REMAINDER,
        help="passed through to pip-audit, e.g. --ignore-vuln <ID>",
    )
    args = parser.parse_args(argv)

    text, stripped, requirements = strip_markers(read_lock(args.lock))
    if requirements == 0:
        print(
            f"::error::{args.lock}: no requirement lines -- refusing an empty audit",
            file=sys.stderr,
        )
        return 2
    options = option_lines(text)
    if options:
        print(f"::error::{args.lock}: pip option lines are not audited: {options}", file=sys.stderr)
        return 2
    continued = continued_requirement_lines(text)
    if continued:
        print(
            f"::error::{args.lock}: a requirement continues onto a line whose marker would not be "
            f"removed: {continued}",
            file=sys.stderr,
        )
        return 2
    print(
        f"{args.lock}: {requirements} pinned requirements, {len(stripped)} un-gated from a marker "
        "the host would have evaluated:"
    )
    for entry in stripped:
        print(f"  {entry}")
    sys.stdout.flush()
    pip_check = [*python_module_argv("pip"), "install", "--dry-run", "--ignore-installed"]
    status = run([*pip_check, "--require-hashes", "--quiet", "-r", str(args.lock)])
    if status:
        return status
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP") or None) as tmp:
        copy = Path(tmp) / args.lock.name
        copy.write_text(text, encoding="utf-8")
        audit = [*python_module_argv("pip_audit"), "-r", str(copy), "--desc", "--disable-pip"]
        return run([*audit, "--strict", *args.pip_audit_args])


if __name__ == "__main__":
    sys.exit(main())
