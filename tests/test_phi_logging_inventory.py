# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Structural drift guard for the ``docs/PHI.md`` §7 logging inventory (ASVS 16.1.1 / 16.2.3).

16.1.1 scores the *inventory itself*: "all logs are inventoried, recording what events are logged, the
format, where they are stored, how they are used, how access is controlled, and their retention." 16.2.3
adds that a log stream which can carry sensitive data must be identified as such. Both are satisfied by
the shipped document, so a stream that ships without a row — or a column set that collapses back to a
summary table — is the defect.

This is a pure structural guard (no engine execution, no network, no Qt), on the pattern of
``tests/test_docs_runbooks.py``. It parses the ``### Logging inventory`` section and asserts:

* every default-on / posture-mandatory stream token is named **inside that section**;
* the table header covers the requirement's own six facts, plus a PHI column;
* every log **filter** class ``messagefoundry.logging_setup`` exports is named — so a fourth filter
  added later reds the doc in the same PR that adds it;
* the shipped defaults the inventory calls "default on" really are the defaults;
* none of the retired false claims this sweep deleted has reappeared anywhere in PHI.md.

A planted-omission self-test proves the assertions can fail.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    AlertsSettings,
    DiagnosticsSettings,
    LogFormat,
    LoggingSettings,
    ServiceSettings,
    SyslogProtocol,
)
from messagefoundry.logging_setup import __all__ as _LOGGING_SETUP_EXPORTS
from tests._ast_sites import (
    ArgumentUnplaced,
    argument_for,
    call_sites,
    callee_name,
    code_names,
    code_strings,
    delete_keeping_a_mention,
    keyword_value,
    named_func,
    parse_source,
    source_calls,
)

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "PHI.md"
_HEADING = "### Logging inventory"

#: Every stream / mechanism the inventory must name. A new default-on sink adds a token here AND a row.
_REQUIRED_STREAM_TOKENS = frozenset(
    {
        # durable, store-backed streams
        "audit_log",
        "message_events",
        "connection_event",
        "alert_instance",
        "ack_sent",
        # transient / off-box streams
        "uvicorn",
        "messagefoundry.audit",
        "forward_",
        "[alerts]",
        "LoggingAlertSink",
        "security_notifications_required",
        # access-control + retention facts the requirement's columns demand
        "logs:view",
        "audit:read",
        "monitoring:read",
        "monitoring:diagnose",
        "app_log_days",
        "connection_event_retention_hours",
        "audit_days",
    }
)

#: The requirement's own words, as alternative spellings acceptable in a header cell.
_REQUIRED_HEADER_FACTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("what events are logged", ("event",)),
    ("the format", ("format",)),
    ("where it is stored", ("stor", "where")),
    ("how it is used", ("use",)),
    ("how access is controlled", ("access", "permission", "rbac")),
    ("retention", ("retention",)),
    ("sensitive-data identification (16.2.3)", ("phi", "sensitive")),
)

#: Claims deleted by this sweep. Their reappearance anywhere in PHI.md is the regression.
_RETIRED_CLAIMS = (
    "transport itself is plaintext",
    "syslog transport is plaintext",
    "two handler filters",
    "same two handler filters",
    "[ai].production",
    # #122 / ADR 0162: the engine DOES install a file handler now, when the opt-in [logging].file is
    # set. Both spellings the inventory used to carry are retired, so the absence claim cannot creep
    # back as a copy-edit — a security document asserting an absence that has stopped being true is
    # precisely what this scanner exists to catch.
    "installs no file handler",
    "installs **no file handler**",
    # BACKLOG #1184 (ASVS 14.2.1): PHI.md described the search needle as riding the query string and
    # its removal as future work. Both names are gone from every GET signature; see PHI.md §7 for
    # what survives. Retiring the wording, not the residual.
    "takes the needle as a QUERY PARAMETER",
    "search needle out of the URL is tracked separately",
    # BACKLOG #1184, second pass. §7 named the residual's sender as "an operator's stale bookmark",
    # a population that cannot exist: the parameter was deleted before any first deployment, so no
    # operator ever held a working `?content=` URL to bookmark (CLAUDE.md §0). A hand-crafted URL is
    # the honest sender and is what the paragraph says now. The fragment carries the possessive
    # deliberately -- §5 legitimately narrates bookmarks as the PRE-#1184 leak vector, and a bare
    # "stale bookmark" would red that honest history.
    "an operator's stale bookmark",
    # And it then called the filter chain "the only control left over a shape the product no longer
    # emits" — two sentences after measuring that the chain does NOT scrub that shape. A compensating
    # control resting on a false premise (SDS-3.7); the paragraph now states there is no control.
    "only control left over a shape",
)


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section_7(text: str | None = None) -> str:
    """The whole ``## 7. Logging & PHI redaction`` section (prose + the inventory)."""
    body = _doc_text() if text is None else text
    start = re.search(r"^## 7\. .*$", body, re.MULTILINE)
    assert start is not None, "docs/PHI.md has no '## 7.' section"
    rest = body[start.end() :]
    nxt = re.search(r"^## ", rest, re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


def _inventory_section(text: str | None = None) -> str:
    """The ``### Logging inventory`` block, up to the next ``---``/``## ``/``### `` boundary."""
    body = _doc_text() if text is None else text
    start = body.find(_HEADING)
    assert start != -1, f"docs/PHI.md has no '{_HEADING}' section"
    rest = body[start + len(_HEADING) :]
    end = re.search(r"^(?:---|## |### )", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def _header_cells(section: str) -> list[str]:
    """The cells of every markdown table header row in ``section``."""
    cells: list[str] = []
    lines = section.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if not re.fullmatch(r"\|(?:\s*:?-{2,}:?\s*\|)+", nxt):
            continue
        cells.extend(c.strip().strip("*` ").lower() for c in stripped.strip("|").split("|"))
    return [c for c in cells if c]


# --- reusable assertions (so the self-test can plant an omission) ---------------------------------


def _assert_streams_named(section: str) -> None:
    missing = sorted(t for t in _REQUIRED_STREAM_TOKENS if t not in section)
    assert not missing, (
        f"docs/PHI.md §7 logging inventory does not name: {missing}. Every default-on or "
        "posture-mandatory stream needs its own row (ASVS 16.1.1/16.2.3) — add the row, do not "
        "narrow the guard."
    )


def _assert_header_facts_covered(section: str) -> None:
    cells = _header_cells(section)
    assert cells, "the logging inventory has no markdown table"
    joined = " | ".join(cells)
    missing = [
        label for label, needles in _REQUIRED_HEADER_FACTS if not any(n in joined for n in needles)
    ]
    assert not missing, (
        f"the logging-inventory table header does not cover: {missing}. ASVS 16.1.1 words the "
        f"inventory as events/format/storage/use/access-control/retention; header was {cells}"
    )


def _assert_filters_named(section: str) -> None:
    filters = sorted(n for n in _LOGGING_SETUP_EXPORTS if n.endswith("Filter"))
    assert len(filters) >= 3, f"logging_setup exports only {filters} — the filter chain shrank"
    missing = [f for f in filters if f not in section]
    assert not missing, (
        f"docs/PHI.md §7 does not name the shipped log filters {missing}; logging_setup exports "
        f"{filters}"
    )


# --- tests ----------------------------------------------------------------------------------------


def test_logging_inventory_section_exists() -> None:
    section = _inventory_section()
    assert section.strip(), "the logging-inventory section is empty"
    assert "16.1.1" in section or "16.1.1" in _doc_text(), "the section lost its requirement anchor"


def test_every_shipped_log_stream_is_named_in_the_inventory() -> None:
    """ASVS 16.1.1 — all logs inventoried; 16.2.3 — sensitive-data streams identified."""
    _assert_streams_named(_inventory_section())


def test_inventory_table_covers_the_requirements_full_column_set() -> None:
    _assert_header_facts_covered(_inventory_section())


def test_all_shipped_log_filters_are_documented() -> None:
    """Derived from ``logging_setup.__all__``: a fourth filter must land in the doc with its code."""
    _assert_filters_named(_section_7())


def test_out_of_scope_streams_are_scoped_out_explicitly() -> None:
    """A silent omission is exactly the 16.1.1 defect — the exclusions must be written down.

    Every token here must occur ONLY in the scope-out prose. ``"tee"`` did not: row 3 is titled
    "``messagefoundry.audit`` off-box tee", so deleting the whole "Not in this inventory, and why"
    paragraph still left ``"tee" in section`` True — the tee relay's scope-out, which discloses an
    unfiltered ``basicConfig`` sink holding full message bodies under ``--capture-bodies``, was the
    one thing this test claimed to pin and did not.

    ``"tray.log"`` left this list with BACKLOG #2351: the tray has a row now, and
    ``test_the_tray_file_sink_has_an_inventory_row`` pins it.
    """
    section = _inventory_section()
    for token in ("/metrics", "/ws/stats", "relay_capture", "--capture-bodies"):
        assert token in section, f"§7 no longer states why {token} is outside the inventory"


def test_retired_false_claims_do_not_reappear() -> None:
    text = _doc_text()
    present = [claim for claim in _RETIRED_CLAIMS if claim in text]
    assert not present, f"docs/PHI.md has regressed to retired/false claims: {present}"


def test_default_on_wording_matches_the_shipped_defaults() -> None:
    """A future default flip must force the inventory's "default on" wording to be revisited."""
    diagnostics = DiagnosticsSettings()
    logging_settings = LoggingSettings()
    alerts = AlertsSettings()
    assert diagnostics.connection_events is True, "§7 calls `connection_event` default-on"
    assert diagnostics.response_sent is True, "§7 calls the ack_sent capture default-on"
    assert diagnostics.message_events == "all", (
        "§7 says [diagnostics].message_events defaults to 'all'"
    )
    assert logging_settings.format is LogFormat.TEXT, "§7 says the stdout format defaults to text"
    assert logging_settings.forward_protocol is SyslogProtocol.UDP, (
        "§7 says the forward protocol defaults to udp"
    )
    assert logging_settings.forward_format is LogFormat.JSON, (
        "§7 says the off-box forward format defaults to JSON"
    )
    assert logging_settings.forward_tls_verify is True, "§7 says TLS verification is on by default"
    assert logging_settings.file is None, (
        "§7 calls the engine-managed [logging].file sink OPT-IN; a default-on file sink is a new "
        "at-rest PHI surface and needs its own inventory row (#122, ADR 0162)"
    )
    assert alerts.security_notifications_required is True, (
        "§7 calls the per-user security-event channel posture-mandatory"
    )


def test_forwarding_is_default_on_when_a_collector_is_named() -> None:
    """The inventory states this explicitly; it is a derived value, not a plain default."""
    assert LoggingSettings().forward_enabled is False, "no collector must leave forwarding off"
    named = LoggingSettings(forward_host="127.0.0.1")
    assert named.forward_enabled is True, (
        "§7 says naming a collector turns forwarding on; the derivation changed"
    )


def test_tls_syslog_and_hop_attestation_settings_exist() -> None:
    """The section deletes the 'syslog is plaintext' claim — pin the mechanism that replaced it."""
    fields = LoggingSettings.model_fields
    for field in (
        "forward_protocol",
        "forward_tls_ca_file",
        "forward_tls_verify",
        "forward_tls_client_cert",
        "forward_hop_attested",
        "forward_hop_attested_reason",
    ):
        assert field in fields, f"§7 cites [logging].{field}, which no longer exists"
    assert SyslogProtocol.TLS.value == "tls", "native TLS-syslog (ADR 0080) is gone"
    assert "production_instance" in type(ServiceSettings().security).model_fields, (
        "§7 cites [security].production_instance as the prod-DEBUG gate's key"
    )


def test_guard_detects_a_planted_omission() -> None:
    """Prove the assertions are not vacuous."""
    section = _inventory_section()
    with pytest.raises(AssertionError):
        _assert_streams_named(section.replace("connection_event", ""))
    with pytest.raises(AssertionError):
        _assert_filters_named("")
    stripped_header = re.sub(r"\| Retention \|", "| |", section)
    with pytest.raises(AssertionError):
        _assert_header_facts_covered(stripped_header)


# =================================================================================================
# 16.1.1 — the inventory's completeness, derived from code instead of a hand-written token list
# =================================================================================================


def test_every_message_event_kind_is_named_in_row_6() -> None:
    """Row 6's "what events are logged" cell — the exact column 16.1.1 words — must be complete.

    RULE: the cell enumerated 9 kinds and read as exhaustive, while the engine emitted more. Derived
    from ``MESSAGE_EVENT_KINDS``, itself cross-checked against the string-literal kinds at the
    ``_event`` / ``_event_stmt`` / ``_event_sync`` call sites below. A kind passed to those helpers
    by variable, or written by a raw INSERT, is not cross-checked.
    """
    from messagefoundry.store.store import MESSAGE_EVENT_KINDS

    section = _section_7()
    missing = sorted(kind for kind in MESSAGE_EVENT_KINDS if f"`{kind}`" not in section)
    assert not missing, (
        f"docs/PHI.md §7 row 6 does not name these message_events kinds: {missing}. The cell "
        "presents itself as the complete per-message disposition timeline (ASVS 16.1.1)."
    )


def test_every_audit_floor_event_is_named_as_such_in_row_6() -> None:
    """The compliance FLOOR — the kinds that survive ``[diagnostics].message_events = "off"``.

    RULE: row 6 states the floor **twice** and both statements were maintained by hand, with nothing
    checking either against ``_AUDIT_FLOOR_EVENTS``. A kind could join the floor in code and the doc
    would keep promising a shorter list — the failure mode being an operator who thins their logs
    believing they know what survives. Row 6 names the floor as the thing that "can never be
    thinned", so ASVS 16.1.1 scores it.

    Mutation: add a member to ``_AUDIT_FLOOR_EVENTS`` without touching row 6. Red: named below.
    """
    from messagefoundry.store.store import _AUDIT_FLOOR_EVENTS

    section = _section_7()
    row = next(line for line in section.splitlines() if line.startswith("| **6. `message_events`"))
    missing = sorted(kind for kind in _AUDIT_FLOOR_EVENTS if f"`{kind}`" not in row)
    assert not missing, (
        f"docs/PHI.md §7 row 6 does not name these compliance-floor kinds: {missing}. Row 6 promises "
        "the floor is retained at every verbosity level; a floor member absent from it makes that "
        "promise incomplete. Note the row states the floor TWICE — update both."
    )


#: The store's message_events write helpers. Each backend defines its own, with its own leading
#: parameters (SQLite's ``_event`` takes none, Postgres takes ``conn``, SQL Server takes ``cur``), so
#: the ``event`` slot is read from each file's own ``def`` rather than assumed.
_EVENT_HELPERS = frozenset({"_event", "_event_stmt", "_event_sync"})

#: The one store method that forwards a caller's kind to the helpers. The scan cannot read what a
#: caller passes, so ``check_caller_event_kind`` refuses an undeclared kind there at run time.
_CALLER_KIND_METHOD = "record_message_event"

#: Declared kinds no store writes itself: only a caller writes them, through
#: :data:`_CALLER_KIND_METHOD`. Pinned, so a kind leaving the store's own writes is a visible change.
_CALLER_ONLY_EVENT_KINDS = frozenset({"reply_returned", "reply_timeout"})


def _module_strings(tree: ast.Module) -> dict[str, str]:
    """Module-level names that exactly one top-level assignment binds, to a string literal. A
    rebinding in a nested block, a function's ``global`` write, a def or an import is not seen."""
    bound: dict[str, list[ast.expr]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bound.setdefault(target.id, []).append(value)
    return {
        name: values[0].value
        for name, values in bound.items()
        if len(values) == 1
        and isinstance(values[0], ast.Constant)
        and isinstance(values[0].value, str)
    }


def _local_values(scope: ast.AST, name: str) -> list[ast.expr] | None:
    """Every value ``scope`` assigns to the bare name ``name``, or ``None`` when one of its bindings
    is not a plain assignment this can read (a parameter anywhere in ``scope``, a loop target, an
    augmented assignment, a walrus, a ``with`` target, or a tuple unpacking with a starred part).
    Plain tuple unpacking is read position by position. An import binds no ``Name`` node and is not
    seen."""
    for node in ast.walk(scope):
        if (
            (isinstance(node, ast.arg) and node.arg == name)
            or (
                isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar)
                and node.name == name
            )
            or (
                isinstance(node, ast.Import | ast.ImportFrom)
                and node is not scope
                and any((alias.asname or alias.name) == name for alias in node.names)
                and not isinstance(scope, ast.Module)
            )
        ):
            # A parameter (of the scope or of a def or lambda in it), an ``except ... as``, a
            # ``match`` capture or a local import: bindings with no Name node to read.
            return None
    values: list[ast.expr] = []
    read: set[int] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == name:
                    values.append(node.value)
                    read.add(id(target))
                elif (
                    isinstance(target, ast.Tuple)
                    and isinstance(node.value, ast.Tuple)
                    and len(target.elts) == len(node.value.elts)
                    and not any(
                        isinstance(e, ast.Starred) for e in (*target.elts, *node.value.elts)
                    )
                ):
                    for element, value in zip(target.elts, node.value.elts, strict=True):
                        if isinstance(element, ast.Name) and element.id == name:
                            values.append(value)
                            read.add(id(element))
    stores = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store)
    ]
    if any(id(node) not in read for node in stores):
        return None
    return values


def _string_values(
    expr: ast.expr, scope: ast.AST, module: dict[str, str], resolving: frozenset[str] = frozenset()
) -> set[str] | None:
    """The strings ``expr`` can evaluate to, read without running it, or ``None`` when that cannot be
    read. Read: a string literal, both arms of a conditional expression, a dict literal indexed or
    read with ``.get`` (every value, and the default), a name ``scope`` assigns only those, and a
    module-level name bound once to a literal. A name that depends on itself, which ``resolving``
    tracks, cannot be read."""
    if isinstance(expr, ast.Constant):
        return {expr.value} if isinstance(expr.value, str) else None
    if isinstance(expr, ast.IfExp):
        body = _string_values(expr.body, scope, module, resolving)
        orelse = _string_values(expr.orelse, scope, module, resolving)
        return None if body is None or orelse is None else body | orelse
    table: ast.Dict | None = None
    extra: list[ast.expr] = []
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Dict):
        table = expr.value
    elif (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "get"
        and isinstance(expr.func.value, ast.Dict)
        and not expr.keywords
        and 1 <= len(expr.args) <= 2
    ):
        table = expr.func.value
        extra = expr.args[1:]
    if table is not None:
        found: set[str] = set()
        for value in (*table.values, *extra):
            got = _string_values(value, scope, module, resolving)
            if got is None:
                return None
            found |= got
        # A .get with no default can return None, which no helper accepts as a kind.
        return found if extra or isinstance(expr, ast.Subscript) else None
    if isinstance(expr, ast.Name):
        if expr.id in resolving:
            return None
        values = _local_values(scope, expr.id)
        if values is None:
            return None
        if not values:
            return {module[expr.id]} if expr.id in module else None
        found = set()
        for value in values:
            got = _string_values(value, scope, module, resolving | {expr.id})
            if got is None:
                return None
            found |= got
        return found
    return None


#: One SQL identifier part: bare, or quoted by brackets, double quotes or backticks.
_SQL_NAME_PART = r'(?:\[[^\]]*\]|"[^"]*"|`[^`]*`|\w+)'
#: An INSERT into message_events, in any case, with any conflict clause, and with the table name
#: schema-qualified (``dbo.message_events``) or quoted (``[message_events]``, ``"message_events"``).
_RAW_EVENT_INSERT = re.compile(
    rf"\binsert\b[^;]*?\binto\s+(?:{_SQL_NAME_PART}\s*\.\s*)*"
    r'(?:\[message_events\]|"message_events"|`message_events`|message_events\b)',
    re.IGNORECASE,
)
_SQL_PLACEHOLDER = re.compile(r"\?|\$\d+|%s|:\w+")
_SQL_VALUES_ROW = re.compile(r"\s*\(([^()]*)\)\s*")


def _raw_insert_events(call: ast.Call, sql: str) -> list[ast.expr] | None:
    """The expressions ``call`` binds to the ``event`` column of ``sql``, an INSERT into
    message_events that ``call`` executes as its first argument, one per VALUES row, or ``None``
    when any cannot be placed. The parameters are either one tuple or list (SQLite, pyodbc) or the
    arguments after the statement (asyncpg); every VALUES entry of every row must be a placeholder,
    one per listed column, or the mapping from parameters to columns is not known here. A
    statement this cannot parse, with no column list or no VALUES rows for one, is ``None`` too,
    so its caller counts the write unread."""
    head, _, tail = sql.partition(")")
    columns = [column.strip().strip('[]"`').lower() for column in head.split("(", 1)[-1].split(",")]
    keyword = re.search(r"\bvalues\b", tail, re.IGNORECASE)
    if "event" not in columns or keyword is None:
        return None
    rows: list[list[str]] = []
    pos = keyword.end()
    while (row := _SQL_VALUES_ROW.match(tail, pos)) is not None:
        rows.append([v.strip() for v in row.group(1).split(",")])
        pos = row.end()
        if not tail.startswith(",", pos):
            break
        pos += 1
    else:
        return None  # no row after VALUES, or none after a comma
    if any(
        len(row) != len(columns) or not all(_SQL_PLACEHOLDER.fullmatch(v) for v in row)
        for row in rows
    ):
        return None
    flat = [placeholder for row in rows for placeholder in row]
    numbered = [p for p in flat if p.startswith("$")]
    if numbered and len(numbered) != len(flat):
        return None
    column = columns.index("event")
    # asyncpg numbers its parameters, so ``$n`` names the argument, not the position.
    slots = [
        int(row[column][1:]) - 1 if numbered else index * len(columns) + column
        for index, row in enumerate(rows)
    ]
    rest = call.args[1:]
    if len(rest) == 1 and isinstance(rest[0], ast.Tuple | ast.List):
        params: list[ast.expr] = list(rest[0].elts)
    else:
        params = list(rest)
    last = max(slots)
    if any(isinstance(param, ast.Starred) for param in params[: last + 1]) or last >= len(params):
        return None
    return [params[slot] for slot in slots]


def _event_write_sites(
    tree: ast.Module,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef | ast.Module, ast.AST]]:
    """Every node outside the event helpers' own defs, with the scope its names resolve in: the
    outermost enclosing ``def``, or the module for code at module or class level."""
    sites: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef | ast.Module, ast.AST]] = []

    def visit(node: ast.AST, scope: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                if child.name in _EVENT_HELPERS:
                    continue
                visit(child, child if scope is tree else scope)
            else:
                sites.append((scope, child))
                visit(child, scope)

    visit(tree, tree)
    return sites


def _event_kinds(source: str, shared: dict[str, str] | None = None) -> tuple[set[str], list[str]]:
    """The ``message_events`` kinds a backend source writes, read statically, and, once per write
    whose kind cannot be read that way, the name of the function it is in.

    Read, outside the helpers' own defs: every call to a helper in :data:`_EVENT_HELPERS`, its
    ``event`` argument placed by that helper's own ``def`` (``self`` dropped), and every INSERT into
    message_events executed as a call's first argument, its table name bare, schema-qualified or
    quoted, and the ``event`` column of every VALUES row placed by the statement's column list
    (:func:`_raw_insert_events`; an INSERT it cannot parse counts as unread). The kind is read by
    :func:`_string_values`, so a literal, a module
    constant such as ``VIEWED_EVENT``, and a local variable assigned only literals (the
    routed/unrouted mapping, for one) are all read. A write at module or class level counts too,
    under ``<module>``. Inside a helper's own ``def``, only a string literal it passes another
    helper as ``event`` is read.

    A helper with no ``event`` parameter, a call to a helper the file does not define, an argument
    that cannot be placed (a starred argument at or before the slot, ``event`` through
    ``**kwargs``, or a method helper called through a receiver other than ``self`` or ``cls``,
    ``super()`` included), a reference to a helper that is not a direct call, a string spelling a
    helper's name (``getattr(self, '_event')``), and an INSERT statement that is not a call's first
    argument each fail here, because a skipped site is the blind spot this guard exists to close.

    ``shared`` is another module's :func:`_module_strings`. Only names a top-level ``from ...
    import`` statement binds, not renamed, are looked up in it (Postgres and SQL Server import
    ``VIEWED_EVENT`` from the SQLite store); the module that statement names is not checked. A kind
    held in any other name that is not a literal binding of this source reads as unread.

    Not read, at least: a helper reached under another name, which the reference check refuses only
    when its name is spelled out whole, as an identifier or a string, an INSERT reached through an
    attribute, a module constant rebound in a way :func:`_module_strings` does not see, and SQL
    assembled at run time.
    """
    tree = parse_source(source)
    imported = {
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.asname is None or alias.asname == alias.name
    }
    module = {
        name: value for name, value in (shared or {}).items() if name in imported
    } | _module_strings(tree)
    insert_names = {name for name, text in module.items() if _RAW_EVENT_INSERT.search(text)}
    helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in _EVENT_HELPERS:
            assert node.name not in helpers, f"two {node.name} definitions; name the one meant"
            helpers[node.name] = node
    methods = {
        id(node)
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    receivers: dict[str, bool] = {}
    for helper in helpers.values():
        assert "event" in {a.arg for a in (*helper.args.posonlyargs, *helper.args.args)}, (
            f"{helper.name} has no `event` parameter; re-aim this guard"
        )
        bound = _binds_receiver(helper, methods)
        assert bound is not None, f"{helper.name} is decorated in a way this scan cannot place"
        receivers[helper.name] = bound
    prose = {
        id(stmt.value)
        for stmt in ast.walk(tree)
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
    }
    defining = {
        id(stmt.value)
        for stmt in tree.body
        if isinstance(stmt, ast.Assign | ast.AnnAssign) and stmt.value is not None
    }
    sites = _event_write_sites(tree)
    executed = {
        id(node.args[0]) for _scope, node in sites if isinstance(node, ast.Call) and node.args
    }
    kinds: set[str] = set()
    unread: list[str] = []
    unplaced: list[str] = []
    stray: list[int] = []
    for scope, node in sites:
        is_sql = (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in prose | defining
            and _RAW_EVENT_INSERT.search(node.value)
        ) or (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in insert_names
        )
        if is_sql and id(node) not in executed:
            stray.append(getattr(node, "lineno", 0))
        if not isinstance(node, ast.Call):
            continue
        name = callee_name(node)
        values: list[ast.expr] | None
        if name in _EVENT_HELPERS:
            assert name in helpers, (
                f"a call to {name}, which this source does not define; re-aim the scan"
            )
            through = node.func.value if isinstance(node.func, ast.Attribute) else None
            if receivers[name] and not (
                isinstance(through, ast.Name) and through.id in {"self", "cls"}
            ):
                # Called through a class or another object, the receiver may be an argument, so
                # the slot is not known (S._event(self, ...) shifts every argument by one).
                unplaced.append(ast.unparse(node))
                continue
            try:
                arg = argument_for(node, helpers[name], "event", receiver=receivers[name])
            except ArgumentUnplaced:
                unplaced.append(ast.unparse(node))
                continue
            values = None if arg is None else [arg]
        elif node.args and (
            sql := (
                node.args[0].value
                if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                else module.get(node.args[0].id)
                if isinstance(node.args[0], ast.Name) and node.args[0].id in insert_names
                else None
            )
        ):
            if not _RAW_EVENT_INSERT.search(sql):
                continue
            values = _raw_insert_events(node, sql)
        else:
            continue
        got: set[str] | None = None
        if values is not None:
            got = set()
            for value in values:
                each = _string_values(value, scope, module)
                if each is None:
                    got = None
                    break
                got |= each
        if got is None:
            unread.append(scope.name if not isinstance(scope, ast.Module) else "<module>")
        else:
            kinds |= got
    # A helper's body is not a write site, so a kind it forwards is not read above; a string literal
    # it hands another helper is still written, so read that, as the literal-only scan did.
    for helper in helpers.values():
        for node in ast.walk(helper):
            if not (isinstance(node, ast.Call) and (name := callee_name(node)) in _EVENT_HELPERS):
                continue
            assert name in helpers, (
                f"a call to {name}, which this source does not define; re-aim the scan"
            )
            through = node.func.value if isinstance(node.func, ast.Attribute) else None
            if receivers[name] and not (
                isinstance(through, ast.Name) and through.id in {"self", "cls"}
            ):
                unplaced.append(ast.unparse(node))
                continue
            try:
                arg = argument_for(node, helpers[name], "event", receiver=receivers[name])
            except ArgumentUnplaced:
                unplaced.append(ast.unparse(node))
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                kinds.add(arg.value)
    assert not unplaced, f"event writes whose `event` argument the scan cannot place: {unplaced}"
    assert not stray, (
        f"INSERT INTO message_events text not executed as a call's first argument, at lines "
        f"{sorted(stray)}; the scan cannot read what it writes"
    )
    called = {id(call.func) for call in ast.walk(tree) if isinstance(call, ast.Call)}
    loose = [
        node.lineno
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Attribute | ast.Name)
            and id(node) not in called
            and (node.attr if isinstance(node, ast.Attribute) else node.id) in _EVENT_HELPERS
        )
        # A string spelling a helper's name, as ``getattr(self, '_event')`` does.
        or (isinstance(node, ast.Constant) and node.value in _EVENT_HELPERS)
    ]
    assert not loose, f"event helpers referenced but not called directly, at lines {loose}"
    return kinds, sorted(unread)


def _store_event_kinds() -> dict[str, tuple[set[str], list[str]]]:
    """:func:`_event_kinds` of each backend, the twins reading names they import from store.py."""
    sources = {
        name: (_ROOT / "messagefoundry" / "store" / name).read_text(encoding="utf-8")
        for name in ("store.py", "postgres.py", "sqlserver.py")
    }
    shared = _module_strings(parse_source(sources["store.py"]))
    return {name: _event_kinds(source, shared) for name, source in sources.items()}


def _check_event_kinds(
    written: dict[str, tuple[set[str], list[str]]], declared: frozenset[str]
) -> None:
    """The rule :func:`test_message_event_constant_matches_the_literal_emit_sites` enforces, apart
    from the scan, so its negative control can feed it a planted case.

    Each backend must write a kind, write only declared kinds, leave exactly one write unread, the
    one in :data:`_CALLER_KIND_METHOD`, and write the same kinds as the others; together they must
    write every declared kind but :data:`_CALLER_ONLY_EVENT_KINDS`. The undeclared check runs first,
    so an undeclared kind is blamed on the backend that writes it rather than on its twins."""
    assert declared >= _CALLER_ONLY_EVENT_KINDS, (
        f"_CALLER_ONLY_EVENT_KINDS names undeclared kinds: "
        f"{sorted(_CALLER_ONLY_EVENT_KINDS - declared)}"
    )
    for name, (kinds, unread) in written.items():
        assert kinds, f"{name}: the scan read no message_events kind; it went blind, re-aim it"
        undeclared = sorted(kinds - declared)
        assert not undeclared, (
            f"{name} writes message_events kind(s) not in MESSAGE_EVENT_KINDS: {undeclared}. "
            "Declare each in MESSAGE_EVENT_KINDS and name it in docs/PHI.md section 7 row 6."
        )
        assert unread == [_CALLER_KIND_METHOD], (
            f"{name}: writes whose kind cannot be read statically, by function: {unread}. Only "
            f"one, in {_CALLER_KIND_METHOD}, is expected: pass a literal, a module constant or a "
            "local assigned only literals."
        )
    union = set().union(*(kinds for kinds, _unread in written.values()))
    differ = {name: sorted(union - kinds) for name, (kinds, _unread) in written.items()}
    assert not any(differ.values()), (
        f"the backends write different message_events kinds; each lacks: {differ}"
    )
    unwritten = sorted(declared - _CALLER_ONLY_EVENT_KINDS - union)
    assert not unwritten, (
        f"declared kinds no backend writes: {unwritten}. A kind removed from the store comes out "
        "of MESSAGE_EVENT_KINDS and docs/PHI.md section 7 row 6; one now written only by callers "
        "goes into _CALLER_ONLY_EVENT_KINDS."
    )
    written_anyway = sorted(_CALLER_ONLY_EVENT_KINDS & union)
    assert not written_anyway, (
        f"_CALLER_ONLY_EVENT_KINDS names kinds a backend now writes itself: {written_anyway}"
    )


def test_message_event_constant_matches_the_literal_emit_sites() -> None:
    """The constant is trustworthy only while it tracks the code that writes the rows.

    RULE (BACKLOG #5498): this read ``args[:2]`` of ``_event`` / ``_event_stmt`` calls in every
    backend. Postgres and SQL Server pass ``conn`` / ``cur`` first, so ``event`` sits at ``args[2]``
    there, and SQL Server's ``_event_sync`` was not read at all; a literal undeclared kind written by
    either backend would have passed. Kinds passed as a variable and SQLite's raw INSERT statements
    were not read either. :func:`_event_kinds` says what is read now, and :func:`_check_event_kinds`
    what each backend must satisfy.
    """
    from messagefoundry.store.store import MESSAGE_EVENT_KINDS

    _check_event_kinds(_store_event_kinds(), MESSAGE_EVENT_KINDS)


def test_the_emit_site_scan_reads_every_backend_signature() -> None:
    """Prove the scan reads the ``event`` slot of each backend's helper shape, and nothing else."""
    source = (
        "VIEWED = 'module_kind'\n"
        "class S:\n"
        "    async def _event(self, conn, message_id, event, destination, detail, now): ...\n"
        "    def _event_sync(self, cur, message_id, event, destination, detail, now): ...\n"
        "    def _event_stmt(self, message_id, event, destination, detail, now): ...\n"
        "    async def run(self, conn, cur, flag):\n"
        "        await self._event(conn, 'mid', 'pg_kind', None, 'detail_literal', 0.0)\n"
        "        self._event_sync(cur, 'mid', 'sync_kind', None, None, 0.0)\n"
        "        self._event_stmt('mid', 'stmt_kind', None, None, 0.0)\n"
        "        await self._event(conn, 'mid', event='kw_kind', destination=None, detail=None,"
        " now=0.0)\n"
        "        await self._event(conn, 'mid', VIEWED, None, None, 0.0)\n"
        "        kind = 'if_kind' if flag else 'else_kind'\n"
        "        await self._event(conn, 'mid', kind, None, None, 0.0)\n"
        "        other = {1: 'dict_kind'}.get(flag, 'default_kind')\n"
        "        await self._event(conn, 'mid', other, None, None, 0.0)\n"
        "        conn.execute('INSERT INTO message_events (message_id, ts, event) VALUES (?,?,?)',"
        " ('mid', 0.0, 'raw_kind'))\n"
        "        conn.execute('insert or ignore into message_events (message_id, ts, event)"
        " values ($1,$2,$3)', 'mid', 0.0, 'pg_raw_kind')\n"
        "    async def record_message_event(self, conn, message_id, event):\n"
        "        await self._event(conn, message_id, event, None, None, 0.0)\n"
        "    async def loop_kind(self, conn, kinds):\n"
        "        for each in kinds:\n"
        "            await self._event(conn, 'mid', each, None, None, 0.0)\n"
        "        a, *b, star = ('x', 'y', 'mid', 'real')\n"
        "        await self._event(conn, 'mid', star, None, None, 0.0)\n"
        "        x = x if flag else 'cycle'\n"
        "        await self._event(conn, 'mid', x, None, None, 0.0)\n"
        "        conn.execute('INSERT INTO message_events (message_id, event) VALUES (?, \"k\")',"
        " ('mid',))\n"
        "    lambda self, c: self._event(c, 'mid', 'class_level_kind', None, None, 0.0)\n"
        "self._event(c, 'mid', 'module_level_kind', None, None, 0.0)\n"
    )
    assert _event_kinds(source) == (
        {
            "pg_kind",
            "sync_kind",
            "stmt_kind",
            "kw_kind",
            "module_kind",
            "if_kind",
            "else_kind",
            "dict_kind",
            "default_kind",
            "raw_kind",
            "pg_raw_kind",
            "class_level_kind",
            "module_level_kind",
        },
        ["loop_kind"] * 4 + ["record_message_event"],
    )
    # One helper handing another a literal kind writes it; the kind it forwards is not a site.
    forwarding = (
        "class S:\n"
        "    async def _event(self, conn, message_id, event, destination, detail, now): ...\n"
        "    def _event_stmt(self, message_id, event, destination, detail, now):\n"
        "        self._event(None, message_id, 'helper_kind', destination, detail, now)\n"
        "        return self._event(None, message_id, event, destination, detail, now)\n"
    )
    assert _event_kinds(forwarding) == ({"helper_kind"}, [])
    with pytest.raises(AssertionError, match="no `event` parameter"):
        _event_kinds("def _event(self, conn, message_id, kind): ...\n")
    with pytest.raises(AssertionError, match="does not define"):
        _event_kinds("def f(cur):\n    self._event_sync(cur, 'mid', 'moved', None, None, 0.0)\n")
    helper = "def _event(self, conn, message_id, event, destination, detail, now): ...\n"
    for call in ("_event(*head, 'starred_kind', None, None, 0.0)", "_event(conn, **parts)"):
        with pytest.raises(AssertionError, match="cannot place"):
            _event_kinds(helper + f"def f(conn, head, parts):\n    self.{call}\n")
    with pytest.raises(AssertionError, match="not called directly"):
        _event_kinds(helper + "def f(self):\n    write = self._event\n")
    with pytest.raises(AssertionError, match="not called directly"):
        _event_kinds(
            helper + "def f(self, c):\n"
            "    getattr(self, '_event')(c, 'mid', 'by_name', None, None, 0.0)\n"
        )
    for chosen in (
        "def f(c, x):\n    sql = 'INSERT INTO message_events (event) VALUES (?)' if x else 'y'\n"
        "    c.execute(sql, ('k',))\n",
        "def f(c):\n    c.execute(sql='INSERT INTO message_events (event) VALUES (?)', p=('k',))\n",
    ):
        with pytest.raises(AssertionError, match="not executed as a call's first argument"):
            _event_kinds(chosen)


@pytest.mark.parametrize(
    "table",
    [
        "dbo.message_events",
        "[message_events]",
        "[dbo].[message_events]",
        '"message_events"',
        'public."message_events"',
        "`message_events`",
    ],
)
def test_the_emit_site_scan_reads_a_qualified_or_quoted_table_name(table: str) -> None:
    """A schema-qualified or quoted table name is still an INSERT into message_events: its kind is
    read, and the same text left unexecuted is still refused as stray. The control: another table
    under the same quoting is not read as one."""
    sql = f"INSERT INTO {table} (message_id, event) VALUES (?, ?)"
    source = f"def f(c):\n    c.execute({sql!r}, ('mid', 'qualified_kind'))\n"
    assert _event_kinds(source) == ({"qualified_kind"}, [])
    with pytest.raises(AssertionError, match="not executed as a call's first argument"):
        _event_kinds(f"def f(c):\n    sql = {sql!r} if c else 'y'\n    c.execute(sql, ())\n")
    other = sql.replace("message_events", "message_events_old")
    assert not _RAW_EVENT_INSERT.search(other)


def test_the_emit_site_scan_reads_every_row_of_a_multi_row_insert() -> None:
    """Each VALUES row binds its own ``event``, so every row's kind is read, and one row whose kind
    cannot be read, or one row that is not all placeholders, makes the write unread."""
    rows = "INSERT INTO message_events (message_id, event) VALUES (?, ?), (?, ?)"
    numbered = "INSERT INTO message_events (message_id, event) VALUES ($1, $2), ($3, $4)"
    source = (
        "def f(c, k):\n"
        f"    c.execute({rows!r}, ('m1', 'row_one', 'm2', 'row_two'))\n"
        f"    c.execute({numbered!r}, 'm1', 'pg_one', 'm2', 'pg_two')\n"
        "def g(c, k):\n"
        f"    c.execute({rows!r}, ('m1', 'row_one', 'm2', k))\n"
        "def h(c):\n"
        f"    c.execute({rows.replace('(?, ?), (?, ?)', '(?, ?), (?, 1)')!r}, ('m', 'k', 'm'))\n"
        "def i(c):\n"
        "    c.execute('INSERT INTO message_events VALUES (?, ?)', ('m', 'k'))\n"
    )
    assert _event_kinds(source) == ({"row_one", "row_two", "pg_one", "pg_two"}, ["g", "h", "i"])


def test_the_event_kind_rule_refuses_each_planted_fault() -> None:
    """Negative control for :func:`_check_event_kinds`: the shipped backends satisfy it, so nothing
    there shows each refusal can fire."""
    declared = frozenset({"a", "b", *_CALLER_ONLY_EVENT_KINDS})
    caller = [_CALLER_KIND_METHOD]

    def backends(**kinds: set[str]) -> dict[str, tuple[set[str], list[str]]]:
        found = {"one": {"a", "b"}, "two": {"a", "b"}} | kinds
        return {name: (written, list(caller)) for name, written in found.items()}

    _check_event_kinds(backends(), declared)
    for written, match in (
        (backends(one=set()), "went blind"),
        (backends(two={"a", "b", "zz"}), "two writes message_events kind"),
        (backends(two={"a"}), "write different"),
        (backends(one={"a"}, two={"a"}), "no backend writes"),
        (
            backends(one={"a", "b", "reply_timeout"}, two={"a", "b", "reply_timeout"}),
            "now writes itself",
        ),
        ({"one": ({"a", "b"}, [*caller, "extra"]), "two": ({"a", "b"}, caller)}, "extra"),
        ({"one": ({"a", "b"}, caller * 2), "two": ({"a", "b"}, caller)}, "Only"),
        ({"one": ({"a", "b"}, []), "two": ({"a", "b"}, caller)}, "Only"),
    ):
        with pytest.raises(AssertionError, match=match):
            _check_event_kinds(written, declared)
    with pytest.raises(AssertionError, match="names undeclared"):
        _check_event_kinds(backends(), frozenset({"a", "b"}))


def test_connection_event_row_names_exactly_the_shipped_kinds() -> None:
    """Both directions, so an invented kind is caught as well as a missing one.

    RULE: row 7 listed ``forbidden``, which **no** code path emits (the only ``forbidden`` in the
    tree is the HTTP 403 response BODY, whose event is ``peer_not_allowlisted``), and gave ``closed``
    a reason of ``error`` that ``close_reason`` never takes.
    """
    import re as _re

    from messagefoundry.connection_events import CONNECTION_EVENT_KINDS

    section = _section_7()
    row = next(
        line for line in section.splitlines() if line.startswith("| **7. `connection_event`")
    )
    missing = sorted(kind for kind in CONNECTION_EVENT_KINDS if f"`{kind}`" not in row)
    assert not missing, f"the connection_event row does not name these shipped kinds: {missing}"
    # Scoped to the "what events are logged" CELL — the row's other cells legitimately name column
    # names, wiring hooks and the table itself, none of which are event kinds.
    events_cell = row.strip("|").split("|")[1]
    named = set(_re.findall(r"`([a-z_]+)`", events_cell))
    invented = sorted(
        token
        for token in named
        # `eof` and `frame_deadline` are close_reason VALUES, `on_connection_event` the wiring hook
        # the cell names when explaining which listeners emit at all — none is an event kind. The
        # row names the close reasons on purpose (they are the `closed` kind's whole vocabulary), so
        # a reason has to be exempted here the way `eof` always has been. `idle_timeout` needs no
        # entry: it is a close reason on MLLP AND an event kind on the HTTP listener.
        if token not in CONNECTION_EVENT_KINDS
        and token not in {"eof", "frame_deadline", "on_connection_event"}
    )
    assert not invented, (
        f"the connection_event row names kind(s) no code path emits: {invented}. The shipped "
        f"vocabulary is {sorted(CONNECTION_EVENT_KINDS)}."
    )


def _emit_kind(call: ast.Call) -> ast.expr | None:
    """The kind an ``_emit_event`` call passes: its first positional argument, or ``kind=``."""
    return call.args[0] if call.args else keyword_value(call, "kind")


def _binds_receiver(func: ast.FunctionDef | ast.AsyncFunctionDef, methods: set[int]) -> bool | None:
    """Whether a call through a receiver binds ``func``'s first parameter: True for a method or a
    classmethod, False for a staticmethod or a function outside a class, and ``None`` for a def
    under any other decorator, whose call shape cannot be told from its signature."""
    decorators = {
        node.id if isinstance(node, ast.Name) else ast.unparse(node) for node in func.decorator_list
    }
    if decorators - {"staticmethod", "classmethod"}:
        return None
    return id(func) in methods and "staticmethod" not in decorators


def _forwarded_kinds(tree: ast.Module) -> tuple[set[str], list[int], set[str]]:
    """The literal kinds ``tree``'s connection-event FORWARDERS are called with, the lines of any
    use whose kind the walk cannot read, and the forwarders' names (BACKLOG #5717).

    A forwarder is a ``def`` that passes one of its own parameters to ``_emit_event`` as the kind,
    as the FILE source's ``_quarantine`` does; its call sites' literals are what it emits. Why the
    vocabulary must be derived from the emit sites is stated once in
    :mod:`messagefoundry.connection_events`, under KEEPING IT TRUE.

    Each forwarder's call sites are read through :func:`argument_for`, the receiver bound by its
    decorators. A use is UNREAD, and its line returned, when the walk cannot say what it emits: a
    kind that is not a string literal, a call through a receiver other than ``self`` or ``cls``, a
    def under another decorator, a reference that is not a direct call (an alias, a
    ``functools.partial``) and a string spelling the forwarder's name (``getattr``). A forwarder
    that rebinds the parameter by assignment or a nested parameter, or also passes ``_emit_event``
    a kind that is neither that parameter nor a literal, fails here rather than being read. Other
    rebindings (``except ... as``, a ``match`` capture, an import) are not seen.
    """
    methods = {
        id(node)
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef)
        for node in cls.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    forwarders: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]] = {}
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = {a.arg for a in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)}
        passed = [_emit_kind(call) for call in call_sites(func, "_emit_event")]
        forwarded = {k.id for k in passed if isinstance(k, ast.Name) and k.id in params}
        if not forwarded:
            continue
        assert len(forwarded) == 1, f"{func.name} forwards several parameters as a kind"
        param = forwarded.pop()
        derived = [
            ast.unparse(k)
            for k in passed
            if k is not None
            and not (isinstance(k, ast.Name) and k.id == param)
            and not (isinstance(k, ast.Constant) and isinstance(k.value, str))
        ]
        assert not derived, f"{func.name} also emits a kind the walk cannot read: {derived}"
        rebound = [
            node.lineno
            for node in ast.walk(func)
            if (isinstance(node, ast.Name) and node.id == param and isinstance(node.ctx, ast.Store))
            or (isinstance(node, ast.arg) and node.arg == param and node not in _own_args(func))
        ]
        assert not rebound, f"{func.name} rebinds its kind `{param}` at lines {rebound}"
        assert func.name not in forwarders, f"two forwarders named {func.name}; name the one meant"
        forwarders[func.name] = (func, param)
    namesakes = sorted(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name in forwarders
        and node is not forwarders[node.name][0]
    )
    # A call is matched to its forwarder by name, so another def of that name would be read through
    # the forwarder's signature.
    assert not namesakes, f"defs sharing a forwarder's name: {namesakes}; name the one meant"
    kinds: set[str] = set()
    unread: list[int] = []
    called: set[int] = set()
    for name, (func, param) in forwarders.items():
        receiver = _binds_receiver(func, methods)
        for call in call_sites(tree, name):
            called.add(id(call.func))
            through = call.func.value if isinstance(call.func, ast.Attribute) else None
            if receiver is None or (
                receiver and not (isinstance(through, ast.Name) and through.id in {"self", "cls"})
            ):
                unread.append(call.lineno)
                continue
            try:
                kind = argument_for(call, func, param, receiver=receiver)
            except ArgumentUnplaced:
                kind = None
            if isinstance(kind, ast.Constant) and isinstance(kind.value, str):
                kinds.add(kind.value)
            else:
                unread.append(call.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute | ast.Name) and id(node) not in called:
            if (node.attr if isinstance(node, ast.Attribute) else node.id) in forwarders:
                unread.append(node.lineno)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in forwarders
        ):
            unread.append(node.lineno)
    return kinds, sorted(unread), set(forwarders)


def _own_args(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    args = func.args
    return [
        a for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg) if a
    ]


def _connection_kinds(trees: dict[str, ast.Module]) -> tuple[set[str], dict[str, set[str]]]:
    """The literal connection_event kinds ``trees`` emit, and each tree's forwarders.

    Read: a literal kind passed to ``_emit_event`` directly, a literal ``kind=`` on a call to
    ``_enqueue_connection_event``, ``HttpRequestError`` or ``Refusal`` (``Refusal`` carries the
    refusal kinds the shared listener admission returns for a listener to emit,
    ``transports/admission.py``, vault BACKLOG #2606), and what :func:`_forwarded_kinds` reads.
    A forwarder use the walk cannot read fails here."""
    targets = {"_emit_event", "_enqueue_connection_event", "HttpRequestError", "Refusal"}
    emitted: set[str] = set()
    forwarders: dict[str, set[str]] = {}
    for name, tree in trees.items():
        forwarded, unread, forwarders[name] = _forwarded_kinds(tree)
        assert not unread, (
            f"{name}: connection-event forwarder use(s) whose kind is not a string literal in a "
            f"direct call, at lines {unread}. The walk cannot see what such a use emits, so call "
            "the forwarder directly and pass the kind as a literal."
        )
        emitted |= forwarded
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or callee_name(node) not in targets:
                continue
            kinds = [keyword_value(node, "kind")]
            if callee_name(node) == "_emit_event":
                kinds.append(_emit_kind(node))
            emitted |= {
                k.value for k in kinds if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
    return emitted, forwarders


def test_forwarder_walk_reads_literals_and_refuses_anything_else() -> None:
    """Negative control for :func:`_forwarded_kinds`: the shipped transports pass only literals, so
    nothing there shows each refusal can fire."""
    probe = ast.parse(
        "class S:\n"
        "    async def _quarantine(self, path, read_id, mark, kind, reason):\n"
        "        await self._emit_event(kind, reason=reason)\n"
        "    async def scan(self, k, head):\n"
        "        await self._quarantine(p, i, m, 'by_position', 'r')\n"
        "        await self._quarantine(p, i, m, kind='by_keyword', reason='r')\n"
        "        await self._quarantine(p, i, m, k, 'r')\n"
        "        await self._quarantine(p, i, m, reason='r', kind=k)\n"
        "        await self._quarantine(*head, 'starred', 'r')\n"
        "        q = self._quarantine\n"
        "        functools.partial(self._quarantine, p, i, m, 'partial')\n"
        "        await S._quarantine(self, p, i, m, 'other_receiver', 'r')\n"
        "        await getattr(self, '_quarantine')(p, i, m, 'by_name', 'r')\n"
    )
    assert _forwarded_kinds(probe) == (
        {"by_position", "by_keyword"},
        [7, 8, 9, 10, 11, 12, 13],
        {"_quarantine"},
    )
    reordered = ast.parse(
        "class S:\n"
        "    async def _quarantine(me, kind, /, path, reason):\n"
        "        await me._emit_event(kind, reason=reason)\n"
        "    async def scan(self):\n"
        "        await self._quarantine('first', p, 'not a kind')\n"
        "        await self._quarantine(kind='keyword_on_positional_only')\n"
    )
    assert _forwarded_kinds(reordered) == ({"first"}, [6], {"_quarantine"})
    receiverless = ast.parse(
        "class S:\n"
        "    @staticmethod\n"
        "    async def _quarantine(kind, path, reason):\n"
        "        await emitter._emit_event(kind=kind, reason=reason)\n"
        "    async def scan(self):\n"
        "        await self._quarantine('first', p, 'not a kind')\n"
        "        await S._quarantine('second', p, 'not a kind')\n"
    )
    assert _forwarded_kinds(receiverless) == ({"first", "second"}, [], {"_quarantine"})
    keyword_only = ast.parse(
        "class S:\n"
        "    async def _reject(self, path, *, why, reason):\n"
        "        await self._emit_event(why, reason=reason)\n"
        "    async def scan(self):\n"
        "        await self._reject(p, why='by_keyword', reason='r')\n"
        "        await self._reject(p, 'no slot', reason='r')\n"
    )
    assert _forwarded_kinds(keyword_only) == ({"by_keyword"}, [6], {"_reject"})
    decorated = ast.parse(
        "class S:\n"
        "    @functools.cache\n"
        "    async def _quarantine(self, kind):\n"
        "        await self._emit_event(kind)\n"
        "    async def scan(self):\n"
        "        await self._quarantine('first')\n"
    )
    assert _forwarded_kinds(decorated) == (set(), [6], {"_quarantine"})
    assert _forwarded_kinds(ast.parse("class S:\n    async def f(self):\n        pass\n")) == (
        set(),
        [],
        set(),
    )
    for body, match in (
        ("        kind = 'x'\n        await self._emit_event(kind)\n", "rebinds"),
        (
            "        await self._emit_event(kind)\n        await self._emit_event(kind + '_x')\n",
            "cannot read",
        ),
    ):
        with pytest.raises(AssertionError, match=match):
            _forwarded_kinds(ast.parse("class S:\n    async def _q(self, kind):\n" + body))


def test_connection_kind_walk_reads_each_emit_shape() -> None:
    """Negative control for :func:`_connection_kinds`, the vocabulary test's own wiring."""
    trees = {
        "a.py": ast.parse(
            "class S:\n"
            "    async def _q(self, kind):\n"
            "        await self._emit_event(kind)\n"
            "    async def run(self):\n"
            "        await self._q('forwarded')\n"
            "        await self._emit_event('direct')\n"
            "        await self._emit_event(kind='direct_keyword')\n"
            "        self._enqueue_connection_event(kind='enqueued')\n"
            "        raise HttpRequestError(400, kind='http')\n"
            "        return Refusal(kind='refusal')\n"
        ),
        "b.py": ast.parse("def f():\n    other(kind='not_an_emit_site')\n"),
    }
    emitted, forwarders = _connection_kinds(trees)
    assert emitted == {"forwarded", "direct", "direct_keyword", "enqueued", "http", "refusal"}
    assert forwarders == {"a.py": {"_q"}, "b.py": set()}
    trees["c.py"] = ast.parse(
        "class S:\n"
        "    async def _q(self, kind):\n"
        "        await self._emit_event(kind)\n"
        "    async def run(self, k):\n"
        "        await self._q(k)\n"
    )
    with pytest.raises(AssertionError, match="c.py: connection-event forwarder"):
        _connection_kinds(trees)


def test_connection_event_vocabulary_is_derived_from_the_emit_sites() -> None:
    """Row 7 claims its vocabulary is "asserted against the emit sites"; make that TRUE.

    The only guard derived its truth set from ``messagefoundry_webconsole.pages.monitoring``'s filter
    DROPDOWN, which never opens a ``transports/`` file — so adding ``_emit_event("tls_handshake_failed")``
    and forgetting the dropdown left CI green with an undocumented kind in the stream. Derived here
    from the literal call sites (:func:`_connection_kinds`), and ``CONNECTION_EVENT_KINDS`` (which the
    console reads) is cross-checked against them.
    """
    roots = [
        *(_ROOT / "messagefoundry" / "transports").glob("*.py"),
        _ROOT / "messagefoundry" / "pipeline" / "wiring_runner.py",
    ]
    emitted, forwarders = _connection_kinds(
        {path.name: ast.parse(path.read_text(encoding="utf-8")) for path in sorted(roots)}
    )
    # The FILE source's reject path forwards its kind through `_quarantine` (BACKLOG #5717); a
    # rename must re-aim the walk rather than let its kinds leave it.
    assert "_quarantine" in forwarders.get("file.py", set()), (
        "file.py's _quarantine no longer forwards its kind to _emit_event; re-aim _forwarded_kinds"
    )
    assert emitted, "no literal connection_event kind found — the emit-site walk broke, not the doc"

    section = _section_7()
    row = next(
        line for line in section.splitlines() if line.startswith("| **7. `connection_event`")
    )
    missing = sorted(kind for kind in emitted if f"`{kind}`" not in row)
    assert not missing, (
        f"connection_event kind(s) emitted by the transports but absent from row 7: {missing}. Row 7 "
        "states its vocabulary is complete."
    )
    # The shared vocabulary the store enforces and the console offers must equal the derived truth
    # (BACKLOG #1624), so a new emit site fails here until its kind is declared.
    from messagefoundry.connection_events import CONNECTION_EVENT_KINDS

    assert emitted == CONNECTION_EVENT_KINDS, (
        "CONNECTION_EVENT_KINDS and the shipped emit sites disagree: "
        f"{sorted(CONNECTION_EVENT_KINDS ^ emitted)}"
    )


def test_every_alert_event_type_is_named_in_the_inventory() -> None:
    """Derived from the settings-layer registry, not from a copied list."""
    from messagefoundry.config.settings import _ALERT_EVENT_TYPES

    section = _section_7()
    missing = sorted(name for name in _ALERT_EVENT_TYPES if f"`{name}`" not in section)
    assert not missing, (
        f"alert event type(s) absent from the §7 inventory: {missing} (ASVS 16.1.1 — the inventory "
        "must say what events are logged)."
    )


def test_auto_resolve_inverses_are_described_accurately() -> None:
    """Row 8 said "(plus four auto-resolving inverses)" — wrong in both count and kind.

    ``_record_state`` routes an inverse to ``resolve_alert_instances_for``, never to
    ``upsert_alert_instance`` — so none of them is ever an ``alert_instance`` row at all. (The row
    once also called ``connection_started`` unreachable; the runner raises it since BACKLOG #1741.)
    """
    import ast as _ast

    from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE

    section = _section_7()
    row = next(line for line in section.splitlines() if line.startswith("| **8. `alert_instance`"))
    tree = _ast.parse(
        (_ROOT / "messagefoundry" / "pipeline" / "alert_sinks.py").read_text(encoding="utf-8")
    )
    record_state = named_func(tree, "_record_state")
    calls = {
        n.func.attr
        for n in _ast.walk(record_state)
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
    }
    assert "resolve_alert_instances_for" in calls, (
        "_record_state no longer resolves an inverse through resolve_alert_instances_for; row 8's "
        "description is stale"
    )
    fence_resolve = named_func(tree, "resolve")
    assert "resolve_alert_instances_fenced" in {
        n.func.attr
        for n in _ast.walk(fence_resolve)
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
    }, "the resolve fence no longer writes through resolve_alert_instances_fenced (BACKLOG #4916)"
    assert "resolve_alert_instances_fenced" in row
    # BACKLOG #3269: the staleness sweep resolves an open or acknowledged intake_paused row, so the
    # retention sentence must name it rather than promise no condition ever leaves unasked.
    assert "is never aged out from under an operator" not in row
    assert "staleness sweep (BACKLOG #3269)" in row
    for inverse in sorted(_AUTO_RESOLVE):
        assert f"`{inverse}`" in section, (
            f"the auto-resolve inverse {inverse!r} is named nowhere in §7"
        )
    assert "plus four auto-resolving inverses" not in row, (
        "the retired over-count is back — no inverse is an alert_instance row"
    )
    assert "emitted by no code path" not in row, (
        "row 8 calls connection_started unreachable again; the runner raises it (BACKLOG #1741)"
    )
    assert "never rows here" in row or "never rows" in row, (
        "row 8 must state that an inverse RESOLVES an open instance rather than inserting one"
    )


def test_security_event_types_are_derived_from_the_notifications_module() -> None:
    """Row 12's catalogue, bound to code — the one enumerated column that was hand-typed.

    That is exactly where the wrong token shipped: the row named ``admin_new_ip`` (a fragment of the
    ``[auth].admin_new_ip_step_up`` CONFIG KEY), while the event type was another name. It is
    ``new_address_reverify_required`` since vault BACKLOG #3052.
    """
    from messagefoundry.auth import notifications

    values = {
        value
        for name, value in vars(notifications).items()
        if not name.startswith("_") and name.isupper() and isinstance(value, str)
    }
    assert len(values) >= 8, f"the security-event constant set collapsed to {sorted(values)}"
    section = _section_7()
    row = next(line for line in section.splitlines() if line.startswith("| **12."))
    missing = sorted(value for value in values if f"`{value}`" not in row)
    assert not missing, (
        f"per-user security-event type(s) absent from row 12: {missing}. The row enumerates the "
        "catalogue, so a new SecurityEvent type must land in the same PR (ASVS 16.1.1)."
    )
    events_cell = row.strip("|").split("|")[1]
    named = set(re.findall(r"`([a-z_]+)`", events_cell))
    invented = sorted(named - values)
    assert not invented, (
        f"row 12 names security-event token(s) no constant defines: {invented}. Shipped vocabulary: "
        f"{sorted(values)}."
    )


def test_every_diagnostics_field_is_named_in_the_inventory() -> None:
    """Every diagnostics stream, keyed on the FIELD NAME rather than a hand-maintained token.

    ``audit_all_authz`` is a shipped diagnostics switch named nowhere in §7 — the value pins alone
    could not catch that, because they only checked the fields somebody had thought to list.
    """
    from messagefoundry.config.settings import DiagnosticsSettings

    section = _section_7()
    missing = sorted(name for name in DiagnosticsSettings.model_fields if name not in section)
    assert not missing, (
        f"[diagnostics] field(s) with no mention in the §7 logging inventory: {missing}"
    )


# =================================================================================================
# 16.2.3 — "only store/broadcast logs to documented sinks"
# =================================================================================================

#: Every first-party module permitted to construct a log SINK, and the §7 row or exclusion covering
#: it. A fourth writer must red CI in the PR that adds it — the frozen token list could not do that,
#: which is how ``tray.log`` shipped undocumented.
_ALLOWED_SINK_MODULES: dict[str, str] = {
    "messagefoundry/logging_setup.py": "streams 1 + 2 (stdout/stderr, the off-box syslog forwarder)",
    # #122 / ADR 0162. This module defines the guarded handler CLASSES for stream 1 —
    # GuardedStreamHandler (stdout) and GuardedFileHandler (the opt-in `[logging].file`, a
    # RotatingFileHandler subclass) — which logging_setup constructs, filters and installs. No new
    # DESTINATION: stream 1's row names both, and the same three PHI filters are installed on each.
    # LISTED rather than excluded, because the class that opens and rolls the file genuinely lives
    # here, so a future sink added beside it must still trip this gate.
    "messagefoundry/logging_guard.py": (
        "stream 1 — the guarded handler classes for stdout and the opt-in `[logging].file`"
    ),
    "messagefoundry/tray/__main__.py": (
        "stream 15 — the tray's RotatingFileHandler, tray.log (BACKLOG #2351)"
    ),
    # The ADR 0087 sandbox child is deliberately ABSENT (BACKLOG #1054): it no longer constructs a sink
    # of its own. It calls logging_setup's `configure_stderr_logging`, so the handler — and the filter
    # chain on it — is built by the module already listed above, and stream 2 covers it.
    # 16.2.3's other half: a module that WRITES log CONTENT to an operator-chosen destination is a
    # log sink even though it constructs no logging handler. The support bundle copies an app-log
    # tail out of the ACL'd directory into a zip whose whole purpose is to be handed off.
    "messagefoundry/support/bundle.py": "stream 14 — the support-bundle app-log.txt member",
}

#: Names that construct a log destination, matched as SUFFIXES of the names code uses, the way the
#: old substring scan matched them: ``RotatingFileHandler``, ``WatchedFileHandler`` or a local
#: ``_SafeFileHandler`` subclass all end in ``FileHandler``.
_SINK_NAME_SUFFIXES = ("FileHandler", "SysLogHandler", "SocketHandler", "basicConfig")
#: Not a logging handler, but a log-CONTENT egress path all the same: the zip member that copies an
#: app-log tail out of the ACL'd directory. Keyed on the member NAME rather than on the redactor,
#: because `api/app.py` legitimately calls the same redactor for `GET /logs/tail`, which is stream
#: 1's documented, RBAC-gated, audited API read — not a new sink.
_SINK_LITERAL = "app-log.txt"
#: A string literal that is only a dotted Python name, e.g. ``"logging.handlers.FileHandler"``.
_DOTTED_NAME = re.compile(r"[A-Za-z_][\w.]*")

#: Packages that execute IN THE ENGINE PROCESS. The console is mounted in-process by ``mount_ui``
#: (ADR 0065), so a FileHandler added there would be an engine-process log sink the single-root scan
#: could never see — a latent hole in the test's own stated contract.
_SINK_SCAN_ROOTS = ("messagefoundry", "messagefoundry_webconsole")


def _is_log_sink(source: str) -> bool:
    """Whether CODE in ``source`` names a log destination or writes the app-log member.

    Read from the tree, not the text (BACKLOG #2056). A comment or docstring naming ``FileHandler``
    kept a module in the sink set after its handler was deleted, so a stale inventory row stayed
    green. Three spellings count besides a name in code: an import of the class under any alias, a
    string that names it (a ``dictConfig`` ``"class"`` value), and the app-log member literal.
    """
    tree = parse_source(source)
    literals = code_strings(tree)
    names = code_names(tree) | {
        alias.name.rpartition(".")[2]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    # Only a literal that IS a dotted name (a dictConfig "class" value), never prose that mentions one.
    names |= {lit.rpartition(".")[2] for lit in literals if _DOTTED_NAME.fullmatch(lit)}
    return any(name.endswith(_SINK_NAME_SUFFIXES) for name in names) or _SINK_LITERAL in literals


def _sink_modules() -> set[str]:
    found: set[str] = set()
    for root in _SINK_SCAN_ROOTS:
        base = _ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            # A text pre-filter, so only a few modules are parsed: every code hit is also a text
            # hit, so it cannot drop one. The verdict is _is_log_sink's.
            if any(token in text for token in (*_SINK_NAME_SUFFIXES, _SINK_LITERAL)) and (
                _is_log_sink(text)
            ):
                found.add(path.relative_to(_ROOT).as_posix())
    return found


def test_log_sinks_are_exactly_the_documented_set() -> None:
    """The anti-rot half of 16.2.3, in the direction that matters.

    RULE: a module constructing a log destination must correspond to a §7 row or a named exclusion.
    The completeness assertions were a frozen doc-side token list derived from nothing, so a NEW
    sink never reddened CI — and the suite was green while ``messagefoundry.tray`` wrote a rotating
    log file the inventory neither listed nor scoped out.
    """
    live = _sink_modules()
    known = set(_ALLOWED_SINK_MODULES)
    assert live == known, (
        f"the log-sink module set changed: {sorted(live ^ known)}. A new sink needs a §7 inventory "
        "row (or a named exclusion in 'Not in this inventory, and why') and an entry here, in the "
        "same change — ASVS 16.2.3 is 'only store/broadcast logs to documented sinks'."
    )


def test_every_alert_broadcast_transport_has_an_inventory_row() -> None:
    """The alert fan-out's registry, bound to §7 — nothing tied the two together.

    RULE (16.2.3): a broadcast transport is a documented sink or it does not ship. Rows 10 and 11
    happen to cover both live transports, but a third (the shape ADR 0044 / #146 anticipates) would
    have landed as an undocumented off-box PHI-adjacent sink with the suite green.
    """
    from messagefoundry.config.settings import _ALERT_TRANSPORTS

    row_tokens = {"webhook": "webhook_url", "email": "email_smtp_host"}
    assert set(row_tokens) == set(_ALERT_TRANSPORTS), (
        f"the [alerts] transport registry changed: {sorted(set(row_tokens) ^ set(_ALERT_TRANSPORTS))}. "
        "Add a §7 inventory row for the new broadcast sink and map it here in the same change."
    )
    section = _section_7()
    missing = sorted(token for token in row_tokens.values() if f"`{token}`" not in section)
    assert not missing, f"[alerts] transport(s) with no §7 row token: {missing}"


def test_the_support_bundle_stream_is_inventoried() -> None:
    """The one shipped log-egress path §7 mentioned only inside another row's prose.

    ``messagefoundry support-bundle`` writes an app-log tail into an operator-chosen zip,
    redacted by a FOURTH redactor the inventory never named, with no access control, no retention and
    no filter-chain coverage. 16.2.3 is "only store/broadcast logs to documented sinks".
    """
    from messagefoundry.support import bundle

    section = _section_7()
    assert "support-bundle" in section, "the support bundle has no §7 row"
    row = next(line for line in section.splitlines() if line.startswith("| **14."))
    assert f"**{bundle.DEFAULT_LOG_TAIL_LINES}**" in row, (
        f"the support-bundle row must state the real tail length "
        f"({bundle.DEFAULT_LOG_TAIL_LINES} lines, DEFAULT_LOG_TAIL_LINES)"
    )
    for token in ("app-log.txt", "redact_log_line"):
        assert token in row, f"the support-bundle row must name {token!r}"


# --- code probes (BACKLOG #2056) -----------------------------------------------------------------
# Each reads engine source as CODE. A substring scan read a comment or docstring naming a construct
# as the construct itself, so deleting the code left the probe green.
# test_the_code_probes_fail_when_the_code_is_gone deletes each one and keeps a mention.


def _captures_child_stderr(source: str) -> bool:
    """Whether some call in ``source`` passes ``stderr=<x>.PIPE``."""
    return any(
        keyword.arg == "stderr"
        and isinstance(keyword.value, ast.Attribute)
        and keyword.value.attr == "PIPE"
        for node in ast.walk(parse_source(source))
        if isinstance(node, ast.Call)
        for keyword in node.keywords
    )


def _gates_on_debug(source: str) -> bool:
    """Whether ``source`` calls ``isEnabledFor(<x>.DEBUG)``."""
    return any(
        bool(call.args) and isinstance(call.args[0], ast.Attribute) and call.args[0].attr == "DEBUG"
        for call in call_sites(parse_source(source), "isEnabledFor")
    )


def _inventory_rows(section: str | None = None) -> list[str]:
    """Every numbered stream row of the inventory table, one string per row."""
    body = _inventory_section() if section is None else section
    return [line for line in body.splitlines() if re.match(r"\|\s*\*\*\d+\. ", line)]


def _row_naming(token: str, section: str | None = None) -> str:
    """The one inventory row whose FIRST cell names ``token`` in backticks, exactly."""
    rows = [row for row in _inventory_rows(section) if f"`{token}`" in row.split("|")[1]]
    assert len(rows) == 1, (
        f"the §7 logging inventory has {len(rows)} rows whose stream cell names {token!r}; "
        "it needs exactly one (ASVS 16.1.1)"
    )
    return rows[0]


def _cells(row: str) -> list[str]:
    """The cells of one table row."""
    return row.strip().strip("|").split("|")


def test_every_inventory_row_has_the_headers_cell_count() -> None:
    """A row one cell too wide shifts every later fact a column right, and the last is dropped.

    Row 17 shipped that way for one commit with this file green: the sensitive-data cell did not
    render. No cell of this table may hold a literal pipe, so a plain split counts cells.
    """
    section = _inventory_section()
    width = len(_header_cells(section))
    rows = _inventory_rows(section)
    assert width >= 8, f"read {width} header cells"
    assert len(rows) >= 17, f"read {len(rows)} inventory rows"
    wrong = {
        _cells(row)[0].strip()[:30]: len(_cells(row)) for row in rows if len(_cells(row)) != width
    }
    assert not wrong, f"inventory rows whose cell count is not the header's {width}: {wrong}"


def test_the_tray_file_sink_has_an_inventory_row() -> None:
    """It ships in the wheel and writes a file, so it has a row, with its real posture.

    It was a named exclusion until BACKLOG #2351. A row is checked, and not the whole section, so
    prose that merely mentions the file cannot stand in for the row.
    """
    row = _row_naming("tray.log")
    for token in ("RotatingFileHandler", "TrayLogScrubFilter", "[retention]", "%LOCALAPPDATA%"):
        assert token in row, (
            f"the tray's inventory row does not name {token!r}. messagefoundry.tray ships INSIDE "
            "the wheel as the messagefoundry-tray gui-script and writes a rotating log file. Since "
            "BACKLOG #2092 that file carries tray/logscrub.py's PHI, credential and "
            "control-character scrub, but not the OIDC query-string filter, and it sits outside the "
            "NSSM DataDir ACL and outside every [retention] window."
        )
    tray = (_ROOT / "messagefoundry" / "tray" / "__main__.py").read_text(encoding="utf-8")
    assert source_calls(tray, "RotatingFileHandler"), (
        "the tray no longer writes a rotating log file; remove its inventory row in the same change."
    )


#: The first argument of every ``createOutputChannel(`` call, whatever it is.
_IDE_CHANNEL_ARG = re.compile(r"createOutputChannel\(\s*([^,)]+)")
#: A plain string literal in any of the three TypeScript quote styles, with no interpolation.
_IDE_LITERAL = re.compile(r"""(['"`])([^'"`$\\]+)\1""")


def _channel_names(source: str) -> set[str]:
    """The channel names ``source`` creates. A name that is not a plain literal fails loudly.

    This is a text scan of TypeScript, which the suite has no parser for. A call left in a comment
    over-fires, by asking for a row the code no longer needs.
    """
    names: set[str] = set()
    for arg in _IDE_CHANNEL_ARG.findall(source):
        literal = _IDE_LITERAL.fullmatch(arg.strip())
        assert literal is not None, (
            f"createOutputChannel({arg.strip()}) does not name its channel with a plain string "
            "literal, so this test cannot tell whether docs/PHI.md has a row for it"
        )
        names.add(literal.group(2))
    return names


def _ide_output_channels() -> set[str]:
    """Every output channel name the VS Code extension creates, read from its shipped source."""
    names: set[str] = set()
    for path in (_ROOT / "ide" / "src").rglob("*.ts"):
        if "test" in path.relative_to(_ROOT / "ide" / "src").parts:
            continue
        names |= _channel_names(path.read_text(encoding="utf-8"))
    return names


def test_every_ide_output_channel_has_an_inventory_row() -> None:
    """BACKLOG #2351. An output channel is a log sink on a developer's desktop, so each has a row.

    The set is read from ``ide/src``, so a third channel reds this test until it gets a row. A
    channel named through a constant or a template with a placeholder fails the reader, because
    the name cannot be read. A call the pattern does not see at all, such as one made through an
    alias of ``createOutputChannel``, is still missed.
    """
    channels = _ide_output_channels()
    assert {"MessageFoundry Engine", "MessageFoundry Checks"} <= channels, (
        f"the reader found only {sorted(channels)} in ide/src; it no longer sees the two channels "
        "this test was written against, so it would pass a third one unseen"
    )
    for name in sorted(channels):
        _row_naming(name)


def test_the_ide_channel_reader_can_fail() -> None:
    """A planted omission: with one channel's row removed, the row lookup raises."""
    section = "\n".join(
        line for line in _inventory_section().splitlines() if "MessageFoundry Checks" not in line
    )
    _row_naming("MessageFoundry Engine", section)
    with pytest.raises(AssertionError, match="MessageFoundry Checks"):
        _row_naming("MessageFoundry Checks", section)
    # A name that is only part of an existing row's name is not that row.
    with pytest.raises(AssertionError, match="0 rows"):
        _row_naming("Engine")


def test_the_ide_channel_reader_sees_every_quote_style_and_refuses_a_constant() -> None:
    """Planted source: the three literal forms are read, and a constant fails loudly."""
    planted = (
        'a = vscode.window.createOutputChannel("One", { log: true });\n'
        "b = vscode.window.createOutputChannel('Two');\n"
        "c = vscode.window.createOutputChannel(\n  `Three`,\n);\n"
    )
    assert _channel_names(planted) == {"One", "Two", "Three"}
    for unreadable in ("createOutputChannel(NAME)", "createOutputChannel(`x ${y}`)"):
        with pytest.raises(AssertionError, match="plain string"):
            _channel_names(unreadable)


def test_the_sandbox_worker_stderr_writer_is_filtered_not_disclosed() -> None:
    """§7's filter-coverage claim must match how the ADR 0087 child actually configures logging.

    Two independent mechanisms cover the child's stderr, and §7 states both. In the CHILD: what decides
    the doc is whether it builds its own **unfiltered** handler. It used to: a bare ``basicConfig``,
    whose handler carries no filters, put WARNING+ records from admin-authored Handler code onto
    stream 1's own sink outside the chain, and §7 disclosed that. It now calls
    ``configure_stderr_logging``, which installs the same three filters (BACKLOG #1054), so the
    disclosure must be gone instead. In the PARENT: the child's stderr is no longer *inherited* at all
    (ADR 0176) — it is captured and relayed, with content gated below INFO — so §7's claim now rests on
    that gate too, and the gate is pinned here rather than only described in prose.

    Pinned BOTH ways, because the interesting direction is the regression: a future edit that put
    ``basicConfig`` back would silently reopen the gap, and this reddens and demands §7 say so again.
    """
    from messagefoundry.config.settings import ServiceSettings

    worker = (_ROOT / "messagefoundry" / "pipeline" / "_sandbox_worker.py").read_text(
        encoding="utf-8"
    )
    sandbox = (_ROOT / "messagefoundry" / "pipeline" / "sandbox.py").read_text(encoding="utf-8")
    assert _captures_child_stderr(sandbox), (
        "the child's stderr is no longer captured by the parent — it is inherited raw again, so §7's "
        "'content only at DEBUG' gate does not exist. Revisit §7 and ADR 0176."
    )
    assert _gates_on_debug(sandbox), (
        "the stderr relay no longer gates content on DEBUG. §7 claims the never-log-bodies rule holds "
        "BY CONSTRUCTION here; without this guard that claim rests on operator discipline instead."
    )
    unfiltered = source_calls(worker, "basicConfig")
    text = _doc_text()
    disclosed = "outside the filter chain" in text
    if unfiltered:
        assert disclosed, (
            "the sandbox worker child emits through a bare basicConfig, whose handler carries no "
            "filters, so §7's 'three filters on every record' claim is not true at the source. The "
            "parent's ADR 0176 relay does not cover this: relayed records ride the engine's handlers, "
            "but a record the CHILD writes unredacted is already unredacted on the wire. Say so."
        )
        assert "in the engine process" in text, (
            "the filter-coverage sentence must be scoped to the engine process"
        )
    else:
        assert not disclosed, (
            "the sandbox child installs the filter chain itself; §7 must not still disclose it as a "
            "writer outside the chain — an exclusion that no longer exists reads as an open weakness"
        )
        assert source_calls(worker, "configure_stderr_logging"), (
            "the child neither uses basicConfig nor configure_stderr_logging — it may have no filter "
            "chain at all. Establish which, and say so in §7."
        )
        assert "DEBUG" in _section_7(), (
            "§7 must name the level at which relayed child stderr content appears. Without it the "
            "reader cannot act on the disclosure: they learn content is withheld and not where to "
            "find it, nor that finding it puts full Handler output on a PHI-class log."
        )
    assert ServiceSettings().sandbox.mode == "off", (
        "[sandbox].mode no longer defaults off; §7 describes an OPT-IN posture — revisit it here."
    )


def test_logging_alert_sink_no_ops_are_disclosed() -> None:
    """Row 13 said "every alert"; ``connection_restored`` is a deliberate no-op on this sink.

    RULE: an AlertSink Protocol method whose ``LoggingAlertSink`` implementation emits no record
    produces NO alert record at all when no ``[alerts]`` transport is configured — which contradicts
    both row 13 and stream 1's own "every alert" cell. Derived, so a second silent method reds CI.
    """
    import ast
    import inspect
    import textwrap

    from messagefoundry.pipeline.alerts import LoggingAlertSink

    silent: set[str] = set()
    for name, member in inspect.getmembers(LoggingAlertSink, inspect.isfunction):
        if name.startswith("_"):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(member)))
        logs = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"log", "info", "warning", "error", "critical", "debug"}
            for node in ast.walk(tree)
        )
        if not logs:
            silent.add(name)
    assert silent, "LoggingAlertSink no longer has a silent method; simplify row 13"
    section = _section_7()
    for name in sorted(silent):
        assert f"`{name}`" in section, (
            f"LoggingAlertSink.{name} emits NO log record, so a {name} alert produces no record at "
            "all on the fallback path. Row 13 claims 'every alert' — name the exception."
        )
    assert "deliberate no-op" in section, (
        "row 13 must state that the silent method(s) are a deliberate no-op, not an oversight"
    )


#: Socket-listening transports whose module name differs from the label row 7 uses for it.
_LISTENER_LABELS = {"http_listener": "HTTP"}


def _opens_a_socket_listener(source: str) -> bool:
    """Whether a transport module opens a listening socket: asyncio's ``start_server``, or
    pynetdicom's ``make_server``, which is how the DICOM SCP builds its server."""
    return source_calls(source, "start_server") or source_calls(source, "make_server")


def test_every_socket_listener_that_emits_nothing_is_named_in_row_7() -> None:
    """Row 7 states which listeners this stream actually covers — derive that, don't trust the prose.

    RULE (16.1.1): the row presents itself as the coverage statement for the connection-event stream,
    so a socket listener that emits **no** event must be named as an exception. Nothing derived that:
    the row said the DICOM C-STORE SCP was the only silent listener while the ``ISA``/``IEA``-framed
    X12 inbound was equally silent, so an operator reading it concluded an X12 feed's connects and
    refusals were captured. They were not. BACKLOG #1665 closed that by wiring X12 to the same seven
    kinds its raw-TCP twin emits, so the row's exception list is once again just the DICOM SCP — and
    this guard is what catches the next listener that arrives silent.

    Scoped to modules that open a socket listener in code: asyncio's ``start_server``, or
    pynetdicom's ``make_server`` for the DICOM SCP, which builds its own server class and so
    never calls ``start_server`` (vault BACKLOG #2583). A poll/file source legitimately
    never emits (``SourceConnector.on_connection_event`` defaults to ``None`` precisely so those stay
    byte-identical), so including them would assert something untrue.
    """
    transports = _ROOT / "messagefoundry" / "transports"
    listeners: dict[str, bool] = {}
    for path in sorted(transports.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not _opens_a_socket_listener(source):
            continue
        listeners[path.stem] = source_calls(source, "_emit_event")
    assert listeners, "no socket listener found — the walk broke, not the doc"
    # A set comparison on the module names, not a membership test on anything read from source.
    assert {"dicom"} <= listeners.keys(), "the DICOM SCP left this guard: it is a listener too"
    assert any(listeners.values()), (
        f"no socket listener emits a connection_event at all: {sorted(listeners)}. Row 7 claims the "
        "stream covers several — re-derive the row, not this guard."
    )

    section = _section_7()
    row = next(
        line for line in section.splitlines() if line.startswith("| **7. `connection_event`")
    )
    silent = sorted(mod for mod, emits in listeners.items() if not emits)
    missing = [mod for mod in silent if _LISTENER_LABELS.get(mod, mod).upper() not in row.upper()]
    assert not missing, (
        f"socket listener(s) that emit NO connection_event and are not named as exceptions in row 7: "
        f"{missing}. The row is the stream's coverage statement — an operator reading it would "
        "believe those feeds' connects and refusals are captured. Name them, or wire the sink."
    )


#: Delete-and-watch-it-fail for every code probe above (BACKLOG #2056): ``(module, the code to
#: delete, what replaces it, the probe)``. Each case also appends a comment naming the deleted
#: construct, the mention the old substring scan read as the code.
_CODE_PROBE_DELETIONS: tuple[tuple[str, str, str, Callable[[str], bool]], ...] = (
    (
        "tray/__main__.py",
        "logging.handlers.RotatingFileHandler(",
        "logging.NullHandler(",
        lambda src: source_calls(src, "RotatingFileHandler") or _is_log_sink(src),
    ),
    ("pipeline/sandbox.py", "stderr=subprocess.PIPE", "stderr=None", _captures_child_stderr),
    ("pipeline/sandbox.py", "isEnabledFor(logging.DEBUG)", "isEnabledFor(0)", _gates_on_debug),
    (
        "pipeline/_sandbox_worker.py",
        "\nconfigure_stderr_logging()",
        "\npass",
        lambda src: source_calls(src, "configure_stderr_logging"),
    ),
    (
        "transports/tcp.py",
        "_emit_event(",
        "_other_hook(",
        lambda src: source_calls(src, "_emit_event"),
    ),
    (
        "transports/tcp.py",
        "asyncio.start_server(",
        "asyncio.sleep(",
        _opens_a_socket_listener,
    ),
    ("transports/dicom.py", "ae.make_server(", "ae.other(", _opens_a_socket_listener),
)


@pytest.mark.parametrize(
    ("module", "code", "replacement", "probe"),
    _CODE_PROBE_DELETIONS,
    ids=[f"{m}:{c.strip()[:40]}" for m, c, _r, _p in _CODE_PROBE_DELETIONS],
)
def test_the_code_probes_fail_when_the_code_is_gone(
    module: str, code: str, replacement: str, probe: Callable[[str], bool]
) -> None:
    source = (_ROOT / "messagefoundry" / module).read_text(encoding="utf-8")
    assert probe(source), f"the probe does not see {code!r} in the real {module}"
    mutated = delete_keeping_a_mention(source, code, replacement)
    assert not probe(mutated), f"{module}: a comment naming {code.strip()!r} reads as the code"


def test_the_sink_probe_sees_an_aliased_import_and_a_dict_config_class() -> None:
    """Two spellings the old substring scan caught and a bare name walk would not."""
    assert _is_log_sink("from logging.handlers import RotatingFileHandler as RFH\nh = RFH('x')\n")
    assert _is_log_sink("CFG = {'class': 'logging.handlers.TimedRotatingFileHandler'}\n")
    assert not _is_log_sink("# RotatingFileHandler\nimport logging\n")
    assert not _is_log_sink(
        "import logging\nlogging.info('no longer uses a RotatingFileHandler')\n"
    )


def test_the_sink_probe_reads_a_basic_config_mention_as_no_sink() -> None:
    """A comment spelling ``logging.basicConfig`` made the old scan call the sandbox worker a sink
    and a bare-basicConfig child. The code probes read the same planted comment as neither."""
    worker = (_ROOT / "messagefoundry" / "pipeline" / "_sandbox_worker.py").read_text(
        encoding="utf-8"
    )
    planted = worker + "\n# logging.basicConfig(level=logging.WARNING)\n"
    assert "logging.basicConfig" in planted
    assert not _is_log_sink(planted)
    assert not source_calls(planted, "basicConfig")


def test_the_emit_site_scan_places_numbered_parameters_and_unbound_helpers() -> None:
    """asyncpg's ``$n`` names its argument, so the column position does not; a helper outside a
    class, or a staticmethod, binds no receiver; and a binding with no Name node is unreadable."""
    numbered = (
        "def f(c):\n"
        "    c.execute('INSERT INTO message_events (message_id, ts, event) VALUES ($1, $3, $2)',"
        " 'mid', 'numbered_kind', 0.0)\n"
    )
    assert _event_kinds(numbered) == ({"numbered_kind"}, [])
    unbound = (
        "def _event_sync(cur, message_id, event): ...\n"
        "class S:\n"
        "    @staticmethod\n"
        "    def _event(message_id, event): ...\n"
        "    def run(self, cur):\n"
        "        _event_sync(cur, 'mid', 'module_helper_kind')\n"
        "        self._event('mid', 'static_kind')\n"
    )
    assert _event_kinds(unbound) == ({"module_helper_kind", "static_kind"}, [])
    hidden = (
        "VIEWED = 'module_kind'\n"
        "def _event(message_id, event): ...\n"
        "def f(flag):\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as VIEWED:\n"
        "        pass\n"
        "    _event('mid', VIEWED)\n"
        "def g(flag):\n"
        "    from elsewhere import VIEWED\n"
        "    _event('mid', VIEWED)\n"
        "def h(flag):\n"
        "    match flag:\n"
        "        case 'x' as VIEWED:\n"
        "            _event('mid', VIEWED)\n"
    )
    assert _event_kinds(hidden) == (set(), ["f", "g", "h"])


def test_the_emit_site_scan_refuses_a_helper_called_through_another_receiver() -> None:
    """``S._event(self, ...)`` passes the receiver as an argument, so reading it as a bound call
    takes ``message_id``'s literal as the kind. Refused rather than read one argument off."""
    source = (
        "class S:\n"
        "    async def _event(self, conn, message_id, event, destination, detail, now): ...\n"
        "    async def run(self, conn):\n"
        "        await S._event(self, conn, 'routed', 'undeclared', None, None, 0.0)\n"
    )
    with pytest.raises(AssertionError, match="cannot place"):
        _event_kinds(source)


def test_forwarder_walk_refuses_a_namesake_of_a_forwarder() -> None:
    namesake = ast.parse(
        "class S:\n"
        "    async def _quarantine(self, kind):\n"
        "        await self._emit_event(kind)\n"
        "class Other:\n"
        "    async def _quarantine(self, path, reason, kind): ...\n"
    )
    with pytest.raises(AssertionError, match="sharing a forwarder's name"):
        _forwarded_kinds(namesake)
