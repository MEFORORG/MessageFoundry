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
#: They count by keyword on any call, and by position on a callee the engine defines
#: (:func:`_module_positions`, :func:`_imported_positions`), so a name added here widens both arms.
_LABEL_KEYWORDS = frozenset(
    {"transport", "description", "cell", "connector", "detail", "label", "crossing", "reason"}
)

#: Calls whose labels are not messages. A pydantic ``Field`` description is schema text, and a tray
#: ``MenuItem`` label is a menu caption handed to ``AppendMenuW``; neither is ever logged.
_NOT_MESSAGES = frozenset({"Field", "MenuItem"})

_Positions = dict[str, frozenset[int]]
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _label_hits(params: list[str]) -> frozenset[int]:
    return frozenset(i for i, p in enumerate(params) if p in _LABEL_KEYWORDS)


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, method: bool) -> list[str]:
    params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
    return params[1:] if method and not static else params


def _init_fields(cls: ast.ClassDef) -> list[str]:
    """A class's positional constructor parameters: its own ``__init__``, else its annotated fields
    in order, skipping ``ClassVar`` and ``field(init=False)`` and stopping at ``KW_ONLY``. Inherited
    fields are not seen, so a subclass's positions can be off; no engine case needs them today."""
    for stmt in cls.body:
        if isinstance(stmt, _DEFS) and stmt.name == "__init__":
            return _params(stmt, method=True)
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


def _module_positions(tree: ast.Module) -> tuple[_Positions, _Positions, _Positions]:
    """Where a label arrives POSITIONALLY, for the callees one module defines.

    A helper such as ``add(name, credential, detail, compliant)`` or a dataclass with a ``reason``
    field takes its label by position, which the keyword arm cannot see. Returns three maps from a
    callee name to the argument positions that land on a :data:`_LABEL_KEYWORDS` name: ``bare`` for
    a plain ``f()`` call (functions and classes), ``attr`` for an ``obj.f()`` call (methods, with
    ``self`` dropped unless static, and classes), and ``top`` for the module-level functions and
    classes another module can import."""
    bare: dict[str, set[int]] = {}
    attr: dict[str, set[int]] = {}
    top: dict[str, set[int]] = {}
    methods: set[int] = set()

    def note(table: dict[str, set[int]], name: str, hits: frozenset[int]) -> None:
        if hits:
            table.setdefault(name, set()).update(hits)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            hits = _label_hits(_init_fields(node))
            note(bare, node.name, hits)
            note(attr, node.name, hits)
            for stmt in node.body:
                if isinstance(stmt, _DEFS):
                    methods.add(id(stmt))
                    note(attr, stmt.name, _label_hits(_params(stmt, method=True)))
    for node in ast.walk(tree):
        if isinstance(node, _DEFS) and id(node) not in methods:
            note(bare, node.name, _label_hits(_params(node, method=False)))
    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef):
            note(top, stmt.name, _label_hits(_init_fields(stmt)))
        elif isinstance(stmt, _DEFS):
            note(top, stmt.name, _label_hits(_params(stmt, method=False)))

    def freeze(table: dict[str, set[int]]) -> _Positions:
        return {name: frozenset(hits) for name, hits in table.items()}

    return freeze(bare), freeze(attr), freeze(top)


@functools.cache
def _engine_positions() -> dict[str, _Positions]:
    """The ``top`` positions of every engine module, by dotted module name."""
    return {
        ".".join(path.relative_to(_ENGINE.parent).with_suffix("").parts): _module_positions(
            parse_source(path.read_text(encoding="utf-8"))
        )[2]
        for path in sorted(_ENGINE.rglob("*.py"))
    }


def _imported_positions(tree: ast.Module) -> _Positions:
    """Positions for the engine callees a module imports by an absolute ``from messagefoundry...
    import``, so ``CheckResult(...)`` in ``verify/smoke.py`` resolves to ``verify/model.py`` and not
    to the unrelated ``CheckResult`` in ``checks.py``. A relative import is not followed."""
    engine = _engine_positions()
    out: dict[str, frozenset[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top = engine.get(node.module, {})
            for alias in node.names:
                if alias.name in top:
                    out[alias.asname or alias.name] = top[alias.name]
    return out


def _message_literals(tree: ast.Module) -> list[tuple[int, str]]:
    """Every string literal in a shape that reaches an operator as message text.

    At least these shapes: the message argument of a logging call (``logger.log`` included), the first
    argument of any call to an ``*Error`` / ``*Exception`` / ``*Refused`` class whether or not it is
    raised on the spot, anything inside a ``raise`` expression, and a label (:data:`_LABEL_KEYWORDS`) a
    guard later interpolates, except on a call in :data:`_NOT_MESSAGES`. A label counts by keyword on
    any call, and by position on a callee the module defines or imports from the engine.

    It is a lexical scan, so it CANNOT see text built anywhere else. At least these reach a log unseen:
    a helper's return value, a local variable assigned and then logged, a label appended to a list and
    joined later, a module constant, a positional label to a callee reached by a relative import,
    and a run split across two literals (``"Always " + "On"``, or either side of an
    f-string field). Those were reworded by hand, and a new one can regress with this test green.
    :func:`test_the_tables_the_scan_cannot_see_survive_redaction` pins the ones found."""
    bare, attr, _top = _module_positions(tree)
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
                    at = bare.get(plain) or imported.get(plain, frozenset())
                else:
                    at = attr.get(name, frozenset())
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


#: One planted run per covered shape and per arm, each reachable ONLY through its own shape, plus five
#: it must skip (prose, a module constant, a Field description, a MenuItem label by keyword and by
#: position, a positional argument that does not land on a label, and an attribute call whose name
#: the module defines only as a free function). A sentence start
#: counts ("Set Foo"), because the redaction cannot tell it from a name either.
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
            "class Sink:\n    def put(self, label): pass",
            "Sink().put('OWNER RIGHTS')",  # a method, `self` dropped
            "class ApprovalError(Exception):\n    def __init__(self, status, detail): pass",
            "ApprovalError(409, 'CREATOR OWNER')",  # an own __init__, past the *Error arm
            "class Row:\n    KIND: ClassVar[str] = 'x'\n    label: str",
            "Row('WAN LINK')",  # a ClassVar is not a constructor field
            "from messagefoundry.verify.model import CheckResult",
            "CheckResult('id', 'title', status, 'LINK DOWN')",  # imported from another module
            "seen.add('NOT THIS')",  # an attribute call; `add` here is a free function
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
            "OWNER RIGHTS",
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
            "add('Not This', 'Local Service bind')",
            "class Finding:\n    path: str\n    reason: str",
            "Finding('Not This', 'Null Dacl here')",  # a field by position; `path` is not one
            "class Sink:\n    def put(self, label): pass",
            "Sink().put('Owner Rights')",  # a method, `self` dropped
            "class ApprovalError(Exception):\n    def __init__(self, status, detail): pass",
            "ApprovalError(409, 'Creator Owner')",  # an own __init__, past the *Error arm
            "class Row:\n    KIND: ClassVar[str] = 'x'\n    label: str",
            "Row('Wan Link')",  # a ClassVar is not a constructor field
            "from messagefoundry.verify.model import CheckResult",
            "CheckResult('id', 'title', status, 'Link Down')",  # imported from another module
            "seen.add('Not This')",  # an attribute call; `add` here is a free function
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
            "Owner Rights",
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


def test_the_tables_the_scan_cannot_see_survive_redaction() -> None:
    """Text the lexical scan cannot see that a refusal, alert or log line renders verbatim."""
    from messagefoundry.auth import anchor_path
    from messagefoundry.pipeline import secret_rotation
    from messagefoundry.store import keyprovider_vault, sqlserver
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
    ]
    eaten = {text: redaction.redact(text) for text in texts if redaction.redact(text) != text}
    assert not eaten, eaten


def test_the_out_of_scan_probe_can_fail() -> None:
    # CONTROL: the probe above compares redact() to identity, so a name-shaped label must come back
    # changed. If redact() stopped scrubbing, every row above would pass for the wrong reason.
    as_windows_prints_it = "NT AUTHORITY\\Authenticated Users (S-1-5-11)"
    assert redaction.redact(as_windows_prints_it) != as_windows_prints_it
