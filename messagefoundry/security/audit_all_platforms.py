# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run ``pip-audit`` over a hashed lock so it audits every pin, whatever the pin's marker.

ONE IMPLEMENTATION, TWO CALLERS. It ships in the wheel, stdlib only, so an adopter's CI can run the
code the engine's own gate runs: ``python -P -m messagefoundry.security.audit_all_platforms <lock>``.
The engine's ``security.yml`` reaches it through ``scripts/security/audit_all_platforms.py``, a thin
wrapper that needs no engine install; the ``audit-pin`` job ``messagefoundry-toolkit init`` generates calls
the module when the adopter commits a hashed ``requirements.lock`` (the toolkit's ``scaffold.py``).

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

1. ``pip install --dry-run --ignore-installed --require-hashes --only-binary :all: -r <lock>`` on
   the lock AS COMMITTED. Wheels only, whatever the caller's pip configuration says: a dry-run
   still builds an sdist to read its metadata, and that runs the package's build code in an audit.
   So a pin with no wheel for the host fails here (vault BACKLOG #4083 finding 4).
   This keeps what the old ``pip-audit -r <lock>`` did as a side effect: its pip path dry-run
   installed the lock into a fresh venv, so a pin with a wrong hash or no installable artifact on the
   runner reddened the gate. For ``ci/locks/ci-quality.lock`` that was the only such check in a
   required job. Markers are evaluated here, deliberately: this checks what the host would install.
2. Writes a copy of the lock with the ``; <marker>`` removed from every requirement line, the pins,
   their ``--hash`` options and any comment untouched, into a temporary directory (under
   ``$RUNNER_TEMP`` when set; never committed, never installed), and prints each pin it un-gated.
   The marker is found as pip 26 finds it (vault BACKLOG #3786 L2): pip hands everything from a
   requirement's first word that starts with ``-`` to its option parser, so a ``--hash`` on the
   requirement's own line, after its marker, is an option and stays; then it splits off the marker
   at the first ``;``, in a ``name @ <url>`` requirement too, and at the first ``; `` after a bare
   URL whose scheme pip's ``is_url`` takes, which a bare ``git:`` or ``svn:`` is not. (pip refuses
   a ``name @ <url>`` whose URL holds a ``;``.)
3. ``pip-audit -r <copy> --desc --disable-pip --strict`` plus any extra arguments (``--ignore-vuln
   <ID>`` for a triaged advisory, which therefore goes AFTER the lock).

``--skip-private <name>``, given BEFORE the lock and repeatable, leaves that one pin out of the copy,
and prints it as not audited (vault BACKLOG #3786 finding 1). It is for a package no advisory
database can look up, such as an adopter's private one: ``--strict`` fails such a pin, and
``--ignore-vuln`` cannot clear that, since it names an advisory, not a package. Every other pin is
still looked up under ``--strict``, and step 1 still checks the named one's hashes, so it must be
downloadable from the index pip is configured with. Past refusing the engine and the MessageFoundry
packages this release knows to be published, nothing checks that the named package is in fact
private: like ``--ignore-vuln``, it is the adopter's recorded decision.

WHY STRIPPING IS SOUND HERE. Every pin in a uv export is a version that uv resolved for some
environment the lock covers. The engine's ``[tool.uv] environments`` limits that to CPython 3.14 on
Windows and Linux, so every engine pin is one a supported host can install, and each exported line
carries that environment as its marker. An adopter's lock may cover more (PyPy, cygwin, macOS);
auditing those pins too is accepted: an advisory against one fails loudly and is triaged with
``--ignore-vuln``, while skipping a pin fails silently, which is the defect above.
``--disable-pip`` is not left to the caller: without it pip-audit installs the requirements through
pip on the host, and a Windows-only distribution need not install on Linux.
With it and a hashed file, pip-audit reads the pins as already resolved and refuses any requirement
that lacks a hash. ``--strict`` makes a pin pip-audit could not look up (a release PyPI has removed,
say) fail the audit instead of being skipped.

WHAT IT REFUSES, exit 2: a lock with no requirement lines at all, so an empty input cannot read as
a clean audit; and a pip option line (``-r``, ``-c``, ``-e``, an index URL), which a uv export
never writes and which would resolve against the temporary copy's directory, or escape the strip,
rather than audit what it names (``uv export --no-emit-project`` writes none; a lock tool can
write at least an index URL, ``--trusted-host`` and ``--find-links`` lines unless told not to); and
a requirement that continues onto a line other than a hash, option or comment, where a marker
would stay in place; and a copy from which pip-audit's parser would read a number of requirements
other than the number counted, as ``_pip_audit_requirement_count`` reads it, which says what that
covers; and a copy holding a requirement in which that parser could still find an environment
marker, as ``_pip_audit_may_see_marker`` reads it, which pip-audit would skip unaudited where the
host fails the marker (the ``;`` the strip leaves inside a bare URL's ``#egg=`` fragment, say); and
a ``--skip-private`` that names the engine or another published
MessageFoundry package, a package the lock does not pin, or every pin, or that comes after the lock
as a word of its own (the ``=`` form or an abbreviation there reaches pip-audit, which fails on it
as an unknown option). It does not judge
whether a non-empty lock is complete; released-line-audit carries its own floor for that.

It reads lines as pip does: a requirement or option is any line that does not continue the one
before it (a line ending in a backslash continues, unless it is a comment), indented or not. It
decodes the lock as pip 26 does (vault BACKLOG #3786 L3): by its UTF-8, UTF-16 or UTF-32
byte-order mark; failing one, by a PEP 263 ``coding:`` declaration in a comment on either of the
first two lines, and the copy is written in that encoding too; failing that, as UTF-8, and as the
locale's encoding when it is not UTF-8. Every other copy is written as UTF-8 with a byte-order mark,
which every reader takes first, so pip-audit's parser, whose fallback is the locale and not UTF-8,
reads it as it was decoded. A lock that cannot be read, or that none of those decodes, is refused
with exit 2, as is a declaration naming no codec this Python knows, and a copy that declared codec
cannot write back. None of those refusals prints the codec error's own text, which quotes the byte
or character it failed on.

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
import locale
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Collection, Sequence
from pathlib import Path

from messagefoundry.childenv import engine_environment, non_engine_environment, python_module_argv
from messagefoundry.redaction import safe_exc


def is_requirement_line(line: str) -> bool:
    """A line that starts a requirement: neither blank, a comment nor a pip option.

    Applied to a line that starts a logical line, with its indentation removed: the ``--hash``
    lines a uv export writes under each requirement continue it, so they are never asked.
    """
    return bool(line) and line[0] not in "#-"


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


def _classify(text: str) -> tuple[list[str], list[str]]:
    """``text``'s physical lines, each with its terminator, and each line's kind (:func:`_kinds`).

    :func:`main` classifies a lock once and reads every answer from that one list (vault BACKLOG
    #3786 L6), so its refusals and its strip cannot read the same lock two ways.
    """
    lines = text.splitlines(keepends=True)
    return lines, _kinds(lines)


def _lines_of(lines: list[str], kinds: list[str], kind: str) -> list[str]:
    return [_body(ln) for ln, k in zip(lines, kinds, strict=True) if k == kind]


def requirement_lines(text: str) -> list[str]:
    """The lines that start a requirement, without their indentation."""
    return [ln.lstrip() for ln in _lines_of(*_classify(text), "requirement")]


def option_lines(text: str) -> list[str]:
    """The pip option lines (``-r``, ``--index-url``, ...) that start a logical line."""
    return _lines_of(*_classify(text), "option")


def continued_requirement_lines(text: str) -> list[str]:
    """Lines a requirement continues onto that the strip does not rewrite (see :func:`_kinds`)."""
    return _lines_of(*_classify(text), "continued")


#: Longest first: a UTF-32-LE mark begins with the UTF-16-LE one.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
    (codecs.BOM_UTF8, "utf-8-sig"),
)

#: A PEP 263 declaration, as pip 26's ``_decode_req_file`` finds one in a first-two-lines comment.
_CODING = re.compile(rb"coding[:=]\s*([-\w.]+)")


def _decode_lock(raw: bytes) -> tuple[str, str]:
    """The lock as pip decodes it, and the encoding a copy needs to be read back the same way.

    In pip's order: a byte-order mark; a PEP 263 declaration in a comment on either of the first two
    lines, which a copy must keep honouring, so it is written in that encoding; UTF-8; and, when
    UTF-8 fails, the locale's encoding. Any other copy takes a UTF-8 byte-order mark, which outranks
    a declaration the text still carries. Raises ``UnicodeError`` when the chosen encoding does not
    decode the bytes, and ``LookupError`` for a declaration naming an unknown codec.
    """
    copy_encoding = "utf-8-sig"
    codec = next((name for bom, name in _BOMS if raw.startswith(bom)), None)
    if codec is None:
        declared = (_CODING.search(ln) for ln in raw.split(b"\n")[:2] if ln[:1] == b"#")
        cookie = next((m for m in declared if m is not None), None)
        if cookie is not None:
            codec = copy_encoding = cookie[1].decode("ascii")
    if codec is not None:
        text = raw.decode(codec)
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode(locale.getencoding() or sys.getdefaultencoding())
    # Universal newlines, as Path.read_text gives them.
    return io.StringIO(text, newline=None).read(), copy_encoding


def read_lock(path: Path) -> str:
    """Decode a lock as pip would (see :func:`_decode_lock`)."""
    return _decode_lock(path.read_bytes())[0]


#: pip-requirements-parser 32.0.1's ``BOMS``, in its order: it tries a native UTF-16 mark before a
#: UTF-32-LE one, which begins with it, so this order is not :data:`_BOMS`'s.
_PIP_AUDIT_BOMS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF32, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
)


def _read_as_pip_audit(raw: bytes) -> str | None:
    """The copy as pip-audit reads it, or ``None`` where that depends on pip-audit's locale.

    pip-audit 2.10.1's ``RequirementsFile.from_file`` decodes with pip-requirements-parser 32.0.1's
    ``auto_decode``: by a byte-order mark, in this order; failing one, by a declaration in a comment
    on either of the first two lines of the bytes as written, so a codec that escapes the copy's
    newlines hides its own declaration; failing that, by the locale of the pip-audit process. That
    process is a child whose UTF-8 mode need not be this one's, so this process cannot know that
    last decode, and ``None`` asks the caller to refuse. Newlines are left as they are, as pip-audit
    leaves them. Raises ``UnicodeError`` or ``LookupError`` as the decode it picks does.
    """
    for bom, codec in _PIP_AUDIT_BOMS:
        if raw.startswith(bom):
            return raw[len(bom) :].decode(codec)
    declared = (_CODING.search(ln) for ln in raw.split(b"\n")[:2] if ln[:1] == b"#")
    cookie = next((m for m in declared if m is not None), None)
    return None if cookie is None else raw.decode(cookie[1].decode("ascii"))


#: A comment as pip finds one: at the start of a line, or after whitespace.
_COMMENT = re.compile(r"(^|\s+)#.*$")

#: Fixed, so it names no lock content.
_COUNT_REFUSAL = (
    "its copy would not hand pip-audit's parser the number of requirements counted, or the auditor "
    "cannot tell that it would"
)

#: Fixed, so it names no lock content.
_MARKER_REFUSAL = (
    "its copy holds a requirement in which pip-audit's parser could find an environment marker, "
    "and skip that pin unaudited"
)


def _pip_audit_requirements(text: str) -> list[str] | None:
    """The requirement strings pip-audit reads from ``text``, or ``None`` where this cannot say.

    pip-audit 2.10.1 reads the copy with pip-requirements-parser 32.0.1, whose ``preprocess`` splits
    ``text`` with ``str.splitlines``, joins a line ending in a backslash to the next unless it is a
    comment, stripping the backslashes from both ends of each joined line (``join_lines``), then
    splits each comment off and drops blank lines (``split_comments``, whose ``COMMENT_RE`` is
    :data:`_COMMENT` with a group around the comment). A line left is a requirement when
    ``break_args_options`` leaves it words before the first that starts with ``-``, which is when
    the line does not start with ``-``; those words, joined by a space, are its requirement string.

    Its limits. A line of options alone is ``None``: optparse makes it an editable requirement when
    it finds ``-e`` there, which this does not model. The strip leaves one only where it empties a
    pin, as from ``;<marker> --hash=...``, and the caller refuses it, failing closed. A requirement
    line counts whether or not the parser can parse its options and pin; one it cannot is an
    invalid line, which this does not catch, but pip-audit 2.10.1 refuses a file holding any, so
    such a copy fails the audit after the count is printed rather than passing short.
    """
    logical: list[str] = []
    joined = ""
    for line in text.splitlines():
        comment = _COMMENT.match(line)
        if line.endswith("\\") and not comment:
            joined += line.strip("\\")
            continue
        logical.append(joined + (f" {line}" if comment else line))
        joined = ""
    logical.append(joined)
    requirements: list[str] = []
    for line in logical:
        code = _COMMENT.sub("", line).strip()
        if code.startswith("-"):
            return None
        if code:
            words = code.split(" ")
            first = next((n for n, word in enumerate(words) if word.startswith("-")), len(words))
            requirements.append(" ".join(words[:first]))
    return requirements


def _pip_audit_requirement_count(text: str) -> int | None:
    """How many requirements pip-audit reads from ``text`` (:func:`_pip_audit_requirements`).

    What this catches: a pin the strip leaves ending in a backslash, as ``foo @ <url>\\ ; <marker>``
    does, joins the next pin onto it, so the copy holds one requirement fewer than the lock.
    """
    requirements = _pip_audit_requirements(text)
    return None if requirements is None else len(requirements)


#: What ``urllib.parse.urlsplit`` deletes from anywhere in a URL.
_URL_REMOVED = str.maketrans("", "", "\t\r\n")


def _decoded(requirement: str) -> str:
    """``requirement`` percent-decoded, and with tab, CR and LF removed, until neither changes it.

    ``urllib.parse.urlsplit`` removes those three before it splits, so they can part a ``%3B``.
    Each pass that changes the text shortens it, so the loop ends.
    """
    while (decoded := urllib.parse.unquote(requirement.translate(_URL_REMOVED))) != requirement:
        requirement = decoded
    return requirement


def _pip_audit_may_see_marker(requirement: str) -> bool:
    """Whether pip-requirements-parser 32.0.1 could attach an environment marker to ``requirement``.

    ``requirement`` is a requirement string as :func:`_pip_audit_requirements` gives it. pip-audit
    2.10.1 drops a pin whose ``InstallRequirement.marker`` the host does not satisfy, with no skip
    and no error, so a marker left in the copy is a pin the count says was audited and was not.

    Every marker the parser makes comes through a ``;``. ``parse_reqparts_from_string`` splits one
    off at the first ``; `` after a URL, else at the first ``;``; and ``InstallRequirement`` takes
    ``req.marker`` from a ``packaging`` ``Requirement``, whose grammar starts a marker with a ``;``.
    That ``Requirement`` is read from the requirement string itself, or for a URL or path that is
    not a wheel from its ``#egg=`` or ``&egg=`` fragment, which the strip's ``; `` rule leaves
    whole (``https://h/evil-1.0.tar.gz#egg=evil==1.0;<marker>``), or for a wheel from its file
    name, which ``Link`` percent-decodes twice. A relative ``file:`` URL is re-made from its decoded
    path, so its egg fragment is decoded once and its file name three times. So this answers yes to
    any ``;`` in the string once :func:`_decoded`.

    That answers yes to more than the parser marks: a ``;`` elsewhere in a URL, or a decoded one
    where no route decodes. Each such answer refuses, failing closed. The strip leaves a literal
    ``;`` only in a bare URL, so any other pin is refused here only where it percent-encodes one.
    A pin with a URL fails the audit anyway when pip-audit keeps it: 2.10.1 reports it skipped as
    a URL requirement, which ``--strict`` fails.
    """
    return ";" in _decoded(requirement)


#: The schemes pip 26's ``is_url`` takes for a URL: its four, and each VCS's ``vcs+`` forms.
_URL_SCHEMES = frozenset(
    ["http", "https", "file", "ftp"]
    + [
        f"{vcs}+{scheme}"
        for vcs, schemes in {
            "git": ("http", "https", "ssh", "git", "file"),
            "hg": ("file", "http", "https", "ssh", "static-http"),
            "svn": ("ssh", "http", "https", "svn", "file"),
            "bzr": ("http", "https", "ssh", "sftp", "ftp", "lp", "file"),
        }.items()
        for scheme in schemes
    ]
)


def _split_marker(line: str) -> tuple[str, str, str] | None:
    """``(pin, marker, what follows them)`` for the first line of a requirement with a marker.

    ``line`` carries no terminator and no continuing backslash. What follows is the line's options
    and comment, unchanged, so a ``--hash`` written after the marker survives the strip. ``None``
    when there is no marker.
    """
    comment = _COMMENT.search(line)
    code = line[: comment.start()] if comment else line
    # pip's break_args_options: the options start at the first word that starts with "-".
    words = code.split(" ")
    first = next((n for n, word in enumerate(words) if word.startswith("-")), len(words))
    requirement, options = " ".join(words[:first]), " ".join(words[first:]).strip()
    # pip's parse_req_from_line: "; " after a URL, as pip's is_url judges the whole requirement
    # by the scheme before its first ":", else the first ";", a name @ URL's too.
    stripped = requirement.strip()
    if ":" in stripped and stripped.split(":", 1)[0].lower() in _URL_SCHEMES:
        at = requirement.find("; ")
    else:
        at = requirement.find(";")
    if at < 0:
        return None
    rest = (f" {options}" if options else "") + line[len(code) :]
    return requirement[:at].rstrip(), requirement[at + 1 :].strip(), rest


def _strip(lines: list[str], kinds: list[str]) -> tuple[list[str], list[str], int]:
    """``lines`` with each requirement's marker removed, line for line; the un-gated entries; and
    the requirement count."""
    out: list[str] = []
    stripped: list[str] = []
    requirements = 0
    for line, kind in zip(lines, kinds, strict=True):
        if kind == "requirement":
            requirements += 1
            body = _body(line)
            continued = body.endswith("\\")
            split = _split_marker(body.removesuffix("\\") if continued else body)
            if split is not None:
                pin, marker, rest = split
                stripped.append(f"{pin.lstrip()} ; {marker}")
                kept = (pin + rest).rstrip()
                line = kept + (" \\" if continued else "") + line[len(body) :]
        out.append(line)
    return out, stripped, requirements


def strip_markers(text: str) -> tuple[str, list[str], int]:
    """Return ``(text without markers, the entries whose marker was removed, requirement count)``."""
    out, stripped, requirements = _strip(*_classify(text))
    return "".join(out), stripped, requirements


#: A distribution name at the start of a requirement (PEP 508).
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


def canonical_name(name: str) -> str:
    """``name`` as PEP 503 compares it: runs of ``-``, ``_`` and ``.`` folded to ``-``, lower case."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _drop(
    lines: list[str], kinds: list[str], names: Collection[str]
) -> tuple[list[str], list[tuple[str, str]]]:
    out: list[str] = []
    dropped: list[tuple[str, str]] = []
    dropping = continued = False
    for line, kind in zip(lines, kinds, strict=True):
        body = _body(line)
        if not continued:
            head = body.lstrip()
            match = _NAME.match(head) if kind == "requirement" else None
            name = canonical_name(match[0]) if match else ""
            dropping = bool(name) and name in names
            if dropping:
                dropped.append((name, head.removesuffix("\\").rstrip()))
        if not dropping:
            out.append(line)
        continued = body.endswith("\\") and not body.lstrip().startswith("#")
    return out, dropped


def drop_requirements(text: str, names: Collection[str]) -> tuple[str, list[tuple[str, str]]]:
    """``text`` without each requirement whose canonical name is in ``names``, the lines it
    continues onto included; and each dropped requirement as ``(canonical name, first line)``.
    Where a requirement starts and how far it goes on is read as :func:`_kinds` reads it."""
    out, dropped = _drop(*_classify(text), names)
    return "".join(out), dropped


#: Distribution names this repo's release workflow publishes to PyPI, beside the engine's own.
#: The repository's one record of them: its install-instruction provenance test reads it, and keeps
#: the dated PyPI probe that classified each name.
PUBLISHED_DISTRIBUTIONS: frozenset[str] = frozenset(
    {"messagefoundry-harness", "messagefoundry-toolkit", "messagefoundry-webconsole"}
)

#: The engine is the pin the adopter's tripwire exists to audit, so it is never skipped as private.
#: Nor is a MessageFoundry package this release knows to be published (``PUBLISHED_DISTRIBUTIONS``):
#: an advisory database can look each one up, so skipping it would only hide an advisory against it
#: (BACKLOG #3786). A name published after this release is not in the set.
#: Folded as the requested names are, so a spelling added to the record still matches.
_NEVER_PRIVATE = frozenset(canonical_name(n) for n in {"messagefoundry", *PUBLISHED_DISTRIBUTIONS})


def _skip_private_refusal(private: Collection[str], pip_audit_args: Sequence[str]) -> str | None:
    """Why a ``--skip-private`` request is refused, or ``None``."""
    if "--skip-private" in pip_audit_args:
        # After the lock, argparse hands it to pip-audit, which fails with a usage error that
        # names neither the flag's position nor this module.
        return "--skip-private goes before the lock, not after it"
    named = sorted(_NEVER_PRIVATE.intersection(private))
    return (
        f"--skip-private may not name the engine or a published MessageFoundry package: {named}"
        if named
        else None
    )


def _run(cmd: list[str]) -> int:
    # non_engine_environment: everything outside the engine's MEFOR_* namespace and its named
    # secrets, so pip and pip-audit keep the index, proxy and certificate settings they read from
    # the environment, and an engine secret set on the same runner does not reach them. Built over
    # engine_environment, which drops an empty or relative PYTHONPATH entry: that would put the
    # working directory back on the children's sys.path, which -P keeps off it.
    env = non_engine_environment(engine_environment())
    # The argv is a list and no shell reads it, but it is not all fixed. Written in this module:
    # the module name (pip or pip_audit) and each flag main() writes. From python_module_argv: the
    # interpreter and its child flags, some fixed and some repeated from this process's own flags
    # and environment. From the caller: the lock path (a workflow, the scaffolded audit-pin job or
    # a person names it; security.yml's released-line audit names it after the release tag it read
    # the lock at), and every argument after the lock, passed through to pip-audit. The temporary
    # copy's path is a fresh directory under $RUNNER_TEMP, or the system temp folder, then that
    # lock's file name. Each is one argv item, and each path follows -r as its value.
    return subprocess.run(cmd, check=False, env=env).returncode  # nosec B603 - argv list, no shell


def main(argv: Sequence[str] | None = None, run: Callable[[list[str]], int] = _run) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--skip-private",
        action="append",
        default=[],
        metavar="NAME",
        help="leave this pin out of the audit, for a package no advisory database can look up; "
        "repeatable, and given before the lock",
    )
    parser.add_argument("lock", type=Path, help="the hashed lock to audit")
    parser.add_argument(
        "pip_audit_args",
        nargs=argparse.REMAINDER,
        help="passed through to pip-audit, e.g. --ignore-vuln <ID>",
    )
    args = parser.parse_args(argv)

    try:
        raw = args.lock.read_bytes()
    except OSError as exc:
        print(f"::error::{args.lock}: not readable: {exc}", file=sys.stderr)
        return 2
    try:
        source, copy_encoding = _decode_lock(raw)
    except (UnicodeError, LookupError) as exc:
        # A codec error's own text quotes the byte it failed on (vault BACKLOG #3033, #3185), so
        # safe_exc names it by type, codec and position; a LookupError keeps its type and a
        # bounded text, since the codec name it quotes is the lock's own, of any length.
        print(
            f"::error::{args.lock}: not decodable the way pip decodes a requirements file: "
            f"{safe_exc(exc)}",
            file=sys.stderr,
        )
        return 2
    lines, kinds = _classify(source)
    stripped_lines, stripped, requirements = _strip(lines, kinds)
    if requirements == 0:
        print(
            f"::error::{args.lock}: no requirement lines -- refusing an empty audit",
            file=sys.stderr,
        )
        return 2
    options = _lines_of(lines, kinds, "option")
    if options:
        print(f"::error::{args.lock}: pip option lines are not audited: {options}", file=sys.stderr)
        return 2
    continued = _lines_of(lines, kinds, "continued")
    if continued:
        print(
            f"::error::{args.lock}: a requirement continues onto a line whose marker would not be "
            f"removed: {continued}",
            file=sys.stderr,
        )
        return 2
    # The count is of the lock as committed, which _kinds reads once (L6); the copy is what
    # pip-audit's parser reads (see _pip_audit_requirement_count). Checked here, before _drop reads
    # the stripped lines by the lock's kinds, and again on the copy _drop leaves.
    if _pip_audit_requirement_count("".join(stripped_lines)) != requirements:
        print(f"::error::{args.lock}: {_COUNT_REFUSAL}", file=sys.stderr)
        return 2
    private = {canonical_name(name) for name in args.skip_private}
    refusal = _skip_private_refusal(private, args.pip_audit_args)
    if refusal:
        print(f"::error::{args.lock}: {refusal}", file=sys.stderr)
        return 2
    # _strip rewrote lines one for one and kept each one's continuation, so their kinds stand: the
    # check above refuses a copy where they do not.
    kept, skipped = _drop(stripped_lines, kinds, private)
    unmatched = private - {name for name, _ in skipped}
    if unmatched:
        print(
            f"::error::{args.lock}: --skip-private names a package the lock does not pin: "
            f"{sorted(unmatched)}",
            file=sys.stderr,
        )
        return 2
    if len(skipped) == requirements:
        print(f"::error::{args.lock}: --skip-private leaves no pin to audit", file=sys.stderr)
        return 2
    counted = requirements - len(skipped)
    audited = "".join(kept)
    read = _pip_audit_requirements(audited)
    if read is None or len(read) != counted:
        print(f"::error::{args.lock}: {_COUNT_REFUSAL}", file=sys.stderr)
        return 2
    if any(map(_pip_audit_may_see_marker, read)):
        print(f"::error::{args.lock}: {_MARKER_REFUSAL}", file=sys.stderr)
        return 2
    # A skipped pin is neither counted nor listed as audited.
    stripped = [
        e for e in stripped if not (m := _NAME.match(e)) or canonical_name(m[0]) not in private
    ]
    print(
        f"{args.lock}: {counted} pinned requirements audited, {len(stripped)} "
        "un-gated from a marker the host would have evaluated:"
    )
    for entry in stripped:
        print(f"  {entry}")
    for _, entry in skipped:
        print(f"  not audited, named by --skip-private: {entry}")
    sys.stdout.flush()
    pip_check = [*python_module_argv("pip"), "install", "--dry-run", "--ignore-installed"]
    status = run(
        [*pip_check, "--require-hashes", "--only-binary", ":all:", "--quiet", "-r", str(args.lock)]
    )
    if status:
        return status
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP") or None) as tmp:
        copy = Path(tmp) / args.lock.name
        try:
            # One complete encode call, not write_text: a text stream never finalizes its encoder,
            # and the idna codec holds back the last label until it is final, so a text-mode write
            # dropped everything after the copy's last "." and pip-audit audited only what came
            # before it. Bytes also skip newline translation; pip-audit reads "\n" on every host.
            copy.write_bytes(audited.encode(copy_encoding))
        except UnicodeError as exc:
            print(
                f"::error::{args.lock}: its copy is not writable as {copy_encoding}: "
                f"{safe_exc(exc)}",
                file=sys.stderr,
            )
            return 2
        # The count above is of `audited`, so pip-audit must decode exactly that. A codec whose
        # encode does not round-trip (unicode_escape escapes every newline, raw_unicode_escape a
        # line separator after a backslash) folds pins into a comment, and pip-audit audits fewer
        # than were counted. Comparing the whole text rules that out for every codec, with no list
        # of them. It proves only that both read the same text: how many requirements pip-audit's
        # parser reads from that text is the count check's job, not this one's. The line names
        # neither the codec, which is the lock's own text of any length, nor the error, which
        # quotes what it failed on.
        try:
            faithful = _read_as_pip_audit(copy.read_bytes()) == audited
        except (OSError, UnicodeError, LookupError):
            faithful = False
        if not faithful:
            print(
                f"::error::{args.lock}: its copy does not read back, the way pip-audit reads it, "
                "as the text whose pins were counted",
                file=sys.stderr,
            )
            return 2
        audit = [*python_module_argv("pip_audit"), "-r", str(copy), "--desc", "--disable-pip"]
        return run([*audit, "--strict", *args.pip_audit_args])


if __name__ == "__main__":
    sys.exit(main())
