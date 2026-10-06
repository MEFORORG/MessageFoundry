# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-authored message text never holds a run the PHI name heuristic scrubs.

The PHI redaction (``messagefoundry.redaction._NAME_RUN``) scrubs two to four adjacent ALL-CAPS tokens,
or two to four adjacent Title-case tokens, as a possible patient name. It cannot tell ``DOE JANE`` from
``SMTP AUTH``, or ``Jane Doe`` from ``Backend Services``, so engine text written that way shipped as
``refusing [redacted] over an unencrypted channel`` and ``SMART [redacted] and OAuth2``, and lost the
words an operator needed. Loosening the redaction to keep protocol words was tried and leaked
identifiers through multi-pass pipelines, so the fix is at the source: engine text is worded so the
heuristic never fires on it. This test holds the shapes :func:`_message_literals` names to that, for
both arms.
"""

from __future__ import annotations

import ast
import functools
from pathlib import Path

import pytest

from messagefoundry import redaction
from tests._ast_sites import callee_name, parse_source

_ENGINE = Path(__file__).resolve().parents[1] / "messagefoundry"
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical"})

#: Parameter and field names that carry a label a transport or guard later interpolates into a message.
#: They count by keyword on any call, and by position on a plain ``f()`` call to a function or class
#: the module defines or imports from the engine (:func:`_local_positions`, :func:`_imported_positions`).
_LABEL_KEYWORDS = frozenset(
    {"transport", "description", "cell", "connector", "detail", "label", "crossing", "reason"}
)

#: Calls whose labels are not messages. A pydantic ``Field`` description is schema text, and a tray
#: ``MenuItem`` label is a menu caption handed to ``AppendMenuW``; neither is ever logged.
_NOT_MESSAGES = frozenset({"Field", "MenuItem"})

_Positions = dict[str, frozenset[int]]
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [a.arg for a in fn.args.posonlyargs + fn.args.args]


def _init_fields(cls: ast.ClassDef) -> list[str]:
    """A class's positional constructor parameters: its own ``__init__`` less ``self``, else its
    annotated fields in order, skipping ``ClassVar`` and ``field(init=False)`` and stopping at
    ``KW_ONLY``. Inherited fields and ``field(kw_only=True)`` are not modelled."""
    for stmt in cls.body:
        if isinstance(stmt, _DEFS) and stmt.name == "__init__":
            return _params(stmt)[1:]
    fields: list[str] = []
    for stmt in cls.body:
        if not (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)):
            continue
        annotation = ast.unparse(stmt.annotation)
        if "KW_ONLY" in annotation:
            break
        value = stmt.value
        no_init = (
            isinstance(value, ast.Call)
            and callee_name(value) == "field"
            and any(
                k.arg == "init" and isinstance(k.value, ast.Constant) and k.value.value is False
                for k in value.keywords
            )
        )
        if "ClassVar" not in annotation and not no_init:
            fields.append(stmt.target.id)
    return fields


def _hits(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[int]:
    """The argument positions of a plain call to ``node`` that land on a label name."""
    params = _init_fields(node) if isinstance(node, ast.ClassDef) else _params(node)
    return frozenset(i for i, p in enumerate(params) if p in _LABEL_KEYWORDS)


def _local_positions(tree: ast.Module) -> _Positions:
    """Every function and class the module defines, at any depth, with its label positions (empty
    when it has none). Methods are left out: a method is called as ``obj.m()``, which is not bound."""
    methods = {
        id(stmt)
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for stmt in node.body
        if isinstance(stmt, _DEFS)
    }
    out: dict[str, frozenset[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) or (isinstance(node, _DEFS) and id(node) not in methods):
            out[node.name] = out.get(node.name, frozenset()) | _hits(node)
    return out


@functools.cache
def _engine_positions() -> dict[str, _Positions]:
    """Each engine module's module-level functions and classes with their label positions, by dotted
    name (a package's ``__init__`` under the package). Parsed directly, not through the shared
    ``parse_source`` cache, which holds 16 trees and would only be churned by 290 modules."""
    out: dict[str, _Positions] = {}
    for path in sorted(_ENGINE.rglob("*.py")):
        parts = path.relative_to(_ENGINE.parent).with_suffix("").parts
        module = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        tree = ast.parse(path.read_text(encoding="utf-8").removeprefix("\ufeff"))
        out[module] = {s.name: _hits(s) for s in tree.body if isinstance(s, (ast.ClassDef, *_DEFS))}
    return out


def _imported_positions(tree: ast.Module) -> _Positions:
    """Positions for the engine callees a module imports by an absolute ``from messagefoundry...
    import``, so ``CheckResult(...)`` in ``verify/smoke.py`` resolves to ``verify/model.py`` and not
    to the unrelated ``CheckResult`` in ``checks.py``. A name the importing module does not itself
    define (a re-export) is not followed."""
    engine = _engine_positions()
    out: dict[str, frozenset[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            defined = engine.get(node.module, {})
            for alias in node.names:
                if alias.name in defined:
                    out[alias.asname or alias.name] = defined[alias.name]
    return out


def _message_literals(tree: ast.Module) -> list[tuple[int, str]]:
    """Every string literal in a shape that reaches an operator as message text.

    At least these shapes: the message argument of a logging call (``logger.log`` included), the first
    argument of any call to an ``*Error`` / ``*Exception`` / ``*Refused`` class whether or not it is
    raised on the spot, anything inside a ``raise`` expression, and a label (:data:`_LABEL_KEYWORDS`) a
    guard later interpolates, except on a call in :data:`_NOT_MESSAGES`. A label counts by keyword on
    any call, and by position on a plain ``f()`` call to a function or class the module defines, or
    else imports by an absolute ``from messagefoundry... import``.

    It is a lexical scan, so it CANNOT see text built anywhere else. At least these reach a log unseen:
    a helper's return value, a local variable assigned and then logged, a label appended to a list and
    joined later, a module constant, a run split across two literals (``"Always " + "On"``, or either
    side of an f-string field), and a label passed by position to a method, through a module name
    (``model.CheckResult(...)``), through a relative import or a re-export, or to a field a base class
    declares. Those were reworded by hand, and a new one can regress with this test green.
    :func:`test_the_tables_the_scan_cannot_see_survive_redaction` pins the ones found."""
    local = _local_positions(tree)
    imported = _imported_positions(tree)
    firsts: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = callee_name(node) or ""
            if name in _LOG_METHODS and node.args:
                firsts.append(node.args[0])
            elif name == "log" and len(node.args) >= 2:
                firsts.append(node.args[1])
            elif name.endswith(("Error", "Exception", "Refused")) and node.args:
                firsts.append(node.args[0])
            if name not in _NOT_MESSAGES:
                firsts.extend(k.value for k in node.keywords if k.arg in _LABEL_KEYWORDS)
                plain = callee_name(node, bare_only=True)
                if plain is not None:
                    at = local[plain] if plain in local else imported.get(plain, frozenset())
                    firsts.extend(node.args[i] for i in at if i < len(node.args))
        elif isinstance(node, ast.Raise) and node.exc is not None:
            firsts.append(node.exc)
    found: dict[tuple[int, int], tuple[int, str]] = {}
    for first in firsts:
        for sub in ast.walk(first):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                found[(sub.lineno, sub.col_offset)] = (sub.lineno, sub.value)
    return list(found.values())


def _runs(source: str) -> list[tuple[int, str]]:
    """Every `_NAME_RUN` match in the message literals of ``source``, either arm."""
    return [
        (line, m.group(0))
        for line, text in _message_literals(parse_source(source))
        for m in redaction._NAME_RUN.finditer(text)
    ]


#: One planted run per covered shape and per arm, each reachable ONLY through its own shape, plus the
#: cases it must skip: prose, a module constant, a Field description, a MenuItem label by keyword and
#: by position, arguments that do not land on a label, a local definition shadowing an import, and an
#: attribute call. A sentence start counts ("Set Foo"), because the redaction cannot tell it from a
#: name either.
_CONTROLS = {
    "caps": (
        [
            "logger.warning('refusing SMTP AUTH over %s', x)",  # a logging call
            "logger.log(logging.WARNING, 'MLLP NAK dropped')",  # logger.log
            "exc = RuntimeError('will not ALTER DATABASE')",  # *Error, not raised here
            "exc = OSException('CONTROL SERVER missing')",  # *Exception
            "exc = HopRefused('LDAP SIMPLE bind')",  # *Refused
            "raise build('FHIR HTTP 500')",  # the raise arm: build() matches no other arm
            "guard(transport='DICOM SCP source')",  # a label keyword
            "logger.info('verified TLS on SMTP')",
            "SQL = 'ALTER DATABASE x'",
            "Field(description='INGRESS ROUTED claim')",
            "MenuItem(label='STOP SERVICE')",
            "def add(name, detail): pass",
            "add('NOT THIS', 'LOCAL SERVICE bind')",  # a positional label; `name` is not one
            "class Finding:\n    path: str\n    reason: str",
            "Finding('NOT THIS', 'NULL DACL here')",  # a field by position; `path` is not one
            "class ApprovalError(Exception):\n    def __init__(self, status, detail): pass",
            "ApprovalError(409, 'CREATOR OWNER')",  # an own __init__, past the *Error arm
            "class Row:\n    KIND: ClassVar[str] = 'x'\n    label: str",
            "Row('WAN LINK')",  # a ClassVar is not a constructor field
            "class Opt:\n    made: str = field(init=False)\n    label: str",
            "Opt('PORT OPEN')",  # nor is a field(init=False)
            "class Kw:\n    path: str\n    _: KW_ONLY\n    label: str",
            "Kw('a', 'b', 'NOT THIS')",  # a field after KW_ONLY takes no position
            "from messagefoundry.verify.model import CheckResult",
            "CheckResult('id', 'title', status, 'LINK DOWN')",  # imported from another module
            "from messagefoundry.verify.model import CheckResult as Shadowed",
            "def Shadowed(a, b, c, d): pass",
            "Shadowed('id', 'title', status, 'NOT THIS')",  # a local definition wins
            "seen.add('x', 'NOT THIS')",  # an attribute call is not bound
            "class MenuItem:\n    label: str",
            "MenuItem('NOT THIS')",  # _NOT_MESSAGES holds by position too
        ],
        [
            "ALTER DATABASE",
            "CONTROL SERVER",
            "CREATOR OWNER",
            "DICOM SCP",
            "FHIR HTTP",
            "LDAP SIMPLE",
            "LINK DOWN",
            "LOCAL SERVICE",
            "MLLP NAK",
            "NULL DACL",
            "PORT OPEN",
            "SMTP AUTH",
            "WAN LINK",
        ],
    ),
    "title": (
        [
            "logger.warning('refusing Backend Services over %s', x)",
            "logger.log(logging.WARNING, 'Always On dropped')",
            "exc = RuntimeError('will not reach Vault Transit')",
            "exc = OSException('Test Bench missing')",
            "exc = HopRefused('Set Foo first')",
            "raise build('Browser Forum rule')",
            "guard(transport='Authenticated Users group')",
            "logger.info('verified the test bench')",
            "NAME = 'Jane Doe'",
            "Field(description='Read Field row')",
            "MenuItem(label='Stop Service')",
            "def add(name, detail): pass",
            "add('Not This', 'Local Service bind')",  # a positional label; `name` is not one
            "class Finding:\n    path: str\n    reason: str",
            "Finding('Not This', 'Null Dacl here')",  # a field by position; `path` is not one
            "class ApprovalError(Exception):\n    def __init__(self, status, detail): pass",
            "ApprovalError(409, 'Creator Owner')",  # an own __init__, past the *Error arm
            "class Row:\n    KIND: ClassVar[str] = 'x'\n    label: str",
            "Row('Wan Link')",  # a ClassVar is not a constructor field
            "class Opt:\n    made: str = field(init=False)\n    label: str",
            "Opt('Port Open')",  # nor is a field(init=False)
            "class Kw:\n    path: str\n    _: KW_ONLY\n    label: str",
            "Kw('a', 'b', 'Not This')",  # a field after KW_ONLY takes no position
            "from messagefoundry.verify.model import CheckResult",
            "CheckResult('id', 'title', status, 'Link Down')",  # imported from another module
            "from messagefoundry.verify.model import CheckResult as Shadowed",
            "def Shadowed(a, b, c, d): pass",
            "Shadowed('id', 'title', status, 'Not This')",  # a local definition wins
            "seen.add('x', 'Not This')",  # an attribute call is not bound
            "class MenuItem:\n    label: str",
            "MenuItem('Not This')",  # _NOT_MESSAGES holds by position too
        ],
        [
            "Always On",
            "Authenticated Users",
            "Backend Services",
            "Browser Forum",
            "Creator Owner",
            "Link Down",
            "Local Service",
            "Null Dacl",
            "Port Open",
            "Set Foo",
            "Test Bench",
            "Vault Transit",
            "Wan Link",
        ],
    ),
}


@pytest.mark.parametrize("arm", sorted(_CONTROLS))
def test_the_scan_fires_on_every_shape_it_claims(arm: str) -> None:
    planted, expected = _CONTROLS[arm]
    assert sorted(run for _, run in _runs("\n".join(planted))) == expected


def test_the_pattern_is_the_shipped_one() -> None:
    # The controls above assume exactly these two arms; a third arm, or a changed one, needs its own.
    assert redaction._NAME_RUN.pattern == (
        r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b|\b[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}\b"
    )


_SOURCES = sorted(_ENGINE.rglob("*.py"))


def test_the_scan_has_a_population() -> None:
    # A moved `_ENGINE` path would parametrize nothing and pass. A floor well under the real counts
    # still catches an empty or wrong root.
    assert len(_SOURCES) > 200
    literals = sum(
        len(_message_literals(parse_source(p.read_text(encoding="utf-8")))) for p in _SOURCES
    )
    assert literals > 2000


@pytest.mark.parametrize("path", _SOURCES, ids=lambda p: p.relative_to(_ENGINE).as_posix())
def test_engine_message_text_holds_no_name_run(path: Path) -> None:
    hits = _runs(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs two adjacent ALL-CAPS words, or two "
        "adjacent Title-case words, as a possible patient name, so this text would reach the log "
        "with those words replaced by [redacted]. Reword it: lower-case the words that are not "
        "acronyms or proper nouns, or separate the two, e.g. 'TLS on SMTP', 'SMART backend services'."
    )


def _comma_runs(source: str) -> list[tuple[int, str]]:
    """Every ``_COMMA_NAME_RUN`` match in the message literals of ``source``, either arm."""
    return [
        (line, m.group(0))
        for line, text in _message_literals(parse_source(source))
        for m in redaction._COMMA_NAME_RUN.finditer(text)
    ]


def test_the_comma_scan_fires_on_both_arms() -> None:
    """The comma arm (vault BACKLOG #2784) reads a list of protocol words as a family-comma-given
    name, so it is held to the same rule. A planted run per arm, and a prose control that holds a
    comma between a capital and a lower-case word."""
    planted = "\n".join(
        [
            "raise ValueError('expected AA, AE or AR')",
            "logger.warning('Connection Refused, Retrying now')",
            "logger.info('Connection refused, retrying')",
        ]
    )
    assert sorted(run for _, run in _comma_runs(planted)) == [
        "AA, AE",
        "Connection Refused, Retrying",
    ]


@pytest.mark.parametrize("path", _SOURCES, ids=lambda p: p.relative_to(_ENGINE).as_posix())
def test_engine_message_text_holds_no_comma_name_run(path: Path) -> None:
    hits = _comma_runs(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs a capitalized word, a comma and a second "
        "capitalized word as a possible family-comma-given name, so this text would reach the log "
        "with those words replaced by [redacted]. Reword it: join a list of codes with '/' "
        "(AA/AE/AR), or use a semicolon or brackets where the comma is not a list separator."
    )


def test_the_tables_the_scan_cannot_see_survive_redaction() -> None:
    """Text the lexical scan cannot see that a refusal, alert or log line renders verbatim."""
    from messagefoundry.auth import anchor_path
    from messagefoundry.pipeline import secret_rotation
    from messagefoundry.store import keyprovider_vault, privilege, sqlserver, store
    from messagefoundry.transports import http_auth, smart

    texts = [anchor_path.describe_sid(sid) for sid in anchor_path._WELL_KNOWN_NAMES]
    texts += [label for _, label in secret_rotation._ENV_SECRET_CLASSES]
    texts += [
        keyprovider_vault._VAULT_TRANSIT_CONNECTOR,
        smart.SmartBackendTokenProvider._MISSING_URL,
        http_auth.OAuth2ClientCredentialsProvider._MISSING_URL,
        # The SQL remedies are lower-cased by hand where rendered; a statement that drifts from that
        # rendering would come back with its keywords redacted.
        sqlserver._rcsi_remedy("mefor_test"),
        sqlserver._options_remedy("mefor_test", [name for name, _ in sqlserver._DATABASE_OPTIONS]),
        store.AUDIT_CHAIN_KEYLESS_ROWS,
    ]
    # An audit-table grant is built by a helper and joined into a refusal later, out of the scan.
    texts += [
        privilege.audit_write_grant(right, table)
        for table in privilege.AUDIT_APPEND_ONLY_TABLES
        for right in privilege.SQLSERVER_AUDIT_WRITE_PRIVILEGES
        + privilege.POSTGRES_AUDIT_WRITE_PRIVILEGES
    ]
    eaten = {text: redaction.redact(text) for text in texts if redaction.redact(text) != text}
    assert not eaten, eaten


def test_the_out_of_scan_probe_can_fail() -> None:
    # CONTROL: the probe above compares redact() to identity, so a name-shaped label must come back
    # changed. If redact() stopped scrubbing, every row above would pass for the wrong reason.
    as_windows_prints_it = "NT AUTHORITY\\Authenticated Users (S-1-5-11)"
    assert redaction.redact(as_windows_prints_it) != as_windows_prints_it
