# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Runtime texts that name the insecure-TLS escape also name the posture it needs (vault BACKLOG
#2637).

``MEFOR_ALLOW_INSECURE_TLS`` is honoured only on an instance at ``[security].enforcement = warn``
(:func:`~messagefoundry.config.settings.weakened_tls_escape_permitted`). Under ``enforce``, the
default, and with no posture it changes nothing. A refusal that told an operator to set it without
saying so sent them to set a variable that does nothing on a default instance.

**What the scanner sees.** One call at a time -- a ``raise X(...)``, a ``logger.warning(...)``,
an ``out.append((...))``. A call names the escape when anything in its arguments or keyword
arguments spells the variable in a string, or refers to ``INSECURE_TLS_ESCAPE_ENV`` by name or as
an attribute; that covers f-strings, ``%`` and ``+`` formatting, ``.format``, and a ``%s`` logging
argument. Its text is every string in those arguments that holds a space, so a bare key such as
the ``""`` default of ``os.environ.get`` is not a message. That text must name the posture.

**What it does not see**, at least: docstrings and comments, which are not calls; a message built
in a variable before the call; and the variable imported under another name. A green run is a
statement about the shapes above, not about every text in the package.

**The positive controls are planted and pinned.** The scanner is proved on two planted sources,
one that must be flagged and one that must pass. The tree walk is proved by pinning the files it
must find, so a scanner that silently matches nothing cannot pass by finding nothing to judge."""

from __future__ import annotations

import ast
from pathlib import Path

from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV

_PACKAGE = Path(__file__).resolve().parent.parent / "messagefoundry"
_NAME = "INSECURE_TLS_ESCAPE_ENV"
_POSTURE = "[security].enforcement = warn"

#: Files that must each hold at least one checked text. Pinned so a scanner that matches nothing
#: fails here instead of passing vacuously.
_MUST_FIND = frozenset(
    {
        "auth/ldap.py",
        "pipeline/alert_sinks.py",
        "store/postgres.py",
        "store/sqlserver.py",
        "transports/ai_broker.py",
        "transports/database.py",
        "transports/direct.py",
        "transports/email.py",
        "transports/mllp.py",
        "transports/remotefile.py",
    }
)


def _names_the_escape(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == _NAME
    if isinstance(node, ast.Attribute):
        return node.attr == _NAME
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and INSECURE_TLS_ESCAPE_ENV in node.value
    )


def escape_texts_without_posture(source: str) -> tuple[list[int], int]:
    """Line numbers of calls whose text names the escape but not the posture, and how many calls
    named the escape at all."""
    unposted: list[int] = []
    seen = 0
    for call in ast.walk(ast.parse(source)):
        if not isinstance(call, ast.Call):
            continue
        operands = [*call.args, *(kw.value for kw in call.keywords)]
        nodes = [node for operand in operands for node in ast.walk(operand)]
        if not any(_names_the_escape(node) for node in nodes):
            continue
        texts = [
            node.value
            for node in nodes
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and " " in node.value
        ]
        if not texts:
            continue
        seen += 1
        if _POSTURE not in "".join(texts):
            unposted.append(call.lineno)
    return unposted, seen


def test_the_scanner_flags_a_text_that_omits_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev only)"\n'
        "    )\n"
        "    log.warning('allowed because %s is set', INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise ValueError('set MEFOR_ALLOW_INSECURE_TLS=1 to allow it')\n"
        "    raise ValueError('set %s=1 to allow it' % settings.INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise HTTPException(detail='set {}=1 to allow it'.format(INSECURE_TLS_ESCAPE_ENV))\n"
        "    out.append(('escape', 'MEFOR_ALLOW_INSECURE_TLS is honoured'))\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 6
    assert unposted == [2, 5, 6, 7, 8, 9]


def test_the_scanner_passes_a_text_that_names_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set on an instance at "\n'
        '        "[security].enforcement = warn"\n'
        "    )\n"
        "    log.warning(\n"
        "        'allowed because %s is set at [security].enforcement = warn',\n"
        "        INSECURE_TLS_ESCAPE_ENV,\n"
        "    )\n"
        "    os.environ.get(INSECURE_TLS_ESCAPE_ENV, '')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 2
    assert unposted == []


def test_every_runtime_text_naming_the_escape_names_the_posture() -> None:
    failures: list[str] = []
    found: set[str] = set()
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if _NAME not in source and INSECURE_TLS_ESCAPE_ENV not in source:
            continue
        rel = path.relative_to(_PACKAGE).as_posix()
        unposted, seen = escape_texts_without_posture(source)
        if seen:
            found.add(rel)
        failures.extend(f"{rel}:{line}" for line in unposted)
    missing = _MUST_FIND - found
    assert not missing, f"the scan found no escape text in {sorted(missing)}"
    assert not failures, (
        f"these texts name {INSECURE_TLS_ESCAPE_ENV} without saying it works only at "
        f"{_POSTURE!r}: {failures}"
    )
