# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import re
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
    """
    section = _inventory_section()
    for token in ("/metrics", "/ws/stats", "relay_capture", "--capture-bodies", "tray.log"):
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

    RULE: the cell enumerated 9 kinds and read as exhaustive; the engine emits 19. Derived from
    ``MESSAGE_EVENT_KINDS``, itself cross-checked against the literal ``_event`` / ``_event_stmt``
    call sites below, so a new kind cannot ship undocumented.
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


def test_message_event_constant_matches_the_literal_emit_sites() -> None:
    """The constant is trustworthy only while it tracks the code that writes the rows."""
    import ast

    from messagefoundry.store.store import MESSAGE_EVENT_KINDS

    emitted: set[str] = set()
    for name in ("store.py", "postgres.py", "sqlserver.py"):
        source = (_ROOT / "messagefoundry" / "store" / name).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            attr = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else None
            )
            if attr not in {"_event", "_event_stmt"}:
                continue
            for arg in node.args[:2]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    emitted.add(arg.value)
    undeclared = sorted(emitted - set(MESSAGE_EVENT_KINDS))
    assert not undeclared, (
        "message_events kind(s) written by the store but absent from MESSAGE_EVENT_KINDS: "
        f"{undeclared}. Add them to the constant AND to docs/PHI.md §7 row 6."
    )


def test_connection_event_row_names_exactly_the_shipped_kinds() -> None:
    """Both directions, so an invented kind is caught as well as a missing one.

    RULE: row 7 listed ``forbidden``, which **no** code path emits (the only ``forbidden`` in the
    tree is the HTTP 403 response BODY, whose event is ``peer_not_allowlisted``), and gave ``closed``
    a reason of ``error`` that ``close_reason`` never takes.
    """
    pytest.importorskip("messagefoundry_webconsole")
    import re as _re

    from messagefoundry_webconsole.pages.monitoring import _EVENT_KINDS

    section = _section_7()
    row = next(
        line for line in section.splitlines() if line.startswith("| **7. `connection_event`")
    )
    missing = sorted(kind for kind in _EVENT_KINDS if f"`{kind}`" not in row)
    assert not missing, f"the connection_event row does not name these shipped kinds: {missing}"
    # Scoped to the "what events are logged" CELL — the row's other cells legitimately name column
    # names, wiring hooks and the table itself, none of which are event kinds.
    events_cell = row.strip("|").split("|")[1]
    named = set(_re.findall(r"`([a-z_]+)`", events_cell))
    invented = sorted(
        token
        for token in named
        # `eof` is a close_reason, `on_connection_event` the wiring hook the cell names when
        # explaining which listeners emit at all — neither is an event kind.
        if token not in set(_EVENT_KINDS) and token not in {"eof", "on_connection_event"}
    )
    assert not invented, (
        f"the connection_event row names kind(s) no code path emits: {invented}. The shipped "
        f"vocabulary is {sorted(_EVENT_KINDS)}."
    )


def test_connection_event_vocabulary_is_derived_from_the_emit_sites() -> None:
    """Row 7 claims its vocabulary is "asserted against the emit sites"; make that TRUE.

    The only guard derived its truth set from ``messagefoundry_webconsole.pages.monitoring``'s filter
    DROPDOWN, which never opens a ``transports/`` file — so adding ``_emit_event("tls_handshake_failed")``
    and forgetting the dropdown left CI green with an undocumented kind in the stream. Derived here
    from the literal call sites, and the console tuple is kept as a second cross-checked source.
    """
    import ast as _ast

    emitted: set[str] = set()
    targets = {"_emit_event", "_enqueue_connection_event", "HttpRequestError"}
    roots = [
        *(_ROOT / "messagefoundry" / "transports").glob("*.py"),
        _ROOT / "messagefoundry" / "pipeline" / "wiring_runner.py",
    ]
    for path in sorted(roots):
        tree = _ast.parse(path.read_text(encoding="utf-8"))
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            name = (
                node.func.attr
                if isinstance(node.func, _ast.Attribute)
                else node.func.id
                if isinstance(node.func, _ast.Name)
                else None
            )
            if name not in targets:
                continue
            if (
                name == "_emit_event"
                and node.args
                and isinstance(node.args[0], _ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                emitted.add(node.args[0].value)
            for kw in node.keywords:
                if (
                    kw.arg == "kind"
                    and isinstance(kw.value, _ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    emitted.add(kw.value.value)
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
    # Cross-check the console dropdown against the same derived truth, so the two cannot diverge.
    console = pytest.importorskip("messagefoundry_webconsole.pages.monitoring")
    assert set(console._EVENT_KINDS) == emitted, (
        "the console filter tuple and the shipped emit sites disagree: "
        f"{sorted(set(console._EVENT_KINDS) ^ emitted)}"
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

    ``_AUTO_RESOLVE`` has four keys but ``connection_started`` is emitted by no code path, and
    ``_record_state`` routes an inverse to ``resolve_alert_instances_for``, never to
    ``upsert_alert_instance`` — so none of them is ever an ``alert_instance`` row at all.
    """
    import ast as _ast

    from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE

    section = _section_7()
    row = next(line for line in section.splitlines() if line.startswith("| **8. `alert_instance`"))
    tree = _ast.parse(
        (_ROOT / "messagefoundry" / "pipeline" / "alert_sinks.py").read_text(encoding="utf-8")
    )
    record_state = next(
        node
        for node in _ast.walk(tree)
        if isinstance(node, _ast.FunctionDef | _ast.AsyncFunctionDef)
        and node.name == "_record_state"
    )
    calls = {
        n.func.attr
        for n in _ast.walk(record_state)
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
    }
    assert "resolve_alert_instances_for" in calls, (
        "_record_state no longer resolves an inverse through resolve_alert_instances_for; row 8's "
        "description is stale"
    )
    for inverse in sorted(_AUTO_RESOLVE):
        assert f"`{inverse}`" in section, (
            f"the auto-resolve inverse {inverse!r} is named nowhere in §7"
        )
    assert "plus four auto-resolving inverses" not in row, (
        "the retired over-count is back — only three inverses are reachable, and none of them is an "
        "alert_instance row"
    )
    assert "never rows here" in row or "never rows" in row, (
        "row 8 must state that an inverse RESOLVES an open instance rather than inserting one"
    )


def test_security_event_types_are_derived_from_the_notifications_module() -> None:
    """Row 12's catalogue, bound to code — the one enumerated column that was hand-typed.

    That is exactly where the wrong token shipped: the row named ``admin_new_ip`` (a fragment of the
    ``[auth].admin_new_ip_step_up`` CONFIG KEY), while the event type is ``admin_action_new_ip``.
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
    "messagefoundry/tray/__main__.py": (
        "the tray's RotatingFileHandler — named in 'Not in this inventory, and why'"
    ),
    # The ADR 0087 sandbox child is deliberately ABSENT (BACKLOG #1054): it no longer constructs a sink
    # of its own. It calls logging_setup's `configure_stderr_logging`, so the handler — and the filter
    # chain on it — is built by the module already listed above, and stream 2 covers it.
    # 16.2.3's other half: a module that WRITES log CONTENT to an operator-chosen destination is a
    # log sink even though it constructs no logging handler. The support bundle copies a 500-line
    # app-log tail out of the ACL'd directory into a zip whose whole purpose is to be handed off.
    "messagefoundry/support/bundle.py": "stream 14 — the support-bundle app-log.txt member",
}

_SINK_TOKENS = (
    "FileHandler",
    "RotatingFileHandler",
    "TimedRotatingFileHandler",
    "logging.basicConfig",
    "SysLogHandler",
    "SocketHandler",
    # Not a logging handler, but a log-CONTENT egress path all the same: the zip member that copies
    # an app-log tail out of the ACL'd directory. Keyed on the member NAME rather than on the
    # redactor, because `api/app.py` legitimately calls the same redactor for `GET /logs/tail`,
    # which is stream 1's documented, RBAC-gated, audited API read — not a new sink.
    '"app-log.txt"',
)

#: Packages that execute IN THE ENGINE PROCESS. The console is mounted in-process by ``mount_ui``
#: (ADR 0065), so a FileHandler added there would be an engine-process log sink the single-root scan
#: could never see — a latent hole in the test's own stated contract.
_SINK_SCAN_ROOTS = ("messagefoundry", "messagefoundry_webconsole")


def _sink_modules() -> set[str]:
    found: set[str] = set()
    for root in _SINK_SCAN_ROOTS:
        base = _ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if any(token in text for token in _SINK_TOKENS):
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

    ``messagefoundry support-bundle`` writes a 500-line app-log tail into an operator-chosen zip,
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


def test_the_tray_file_sink_is_scoped_out_by_name() -> None:
    """It ships in the wheel, so silence is not an option — it is named, with its real posture."""
    section = _section_7()
    for token in ("tray.log", "RotatingFileHandler"):
        assert token in section, (
            f"§7 does not name {token!r}. messagefoundry.tray ships INSIDE the wheel as the "
            "messagefoundry-tray gui-script and writes a rotating log file with none of the three "
            "handler filters, outside the NSSM DataDir ACL and outside every [retention] window."
        )
    tray = (_ROOT / "messagefoundry" / "tray" / "__main__.py").read_text(encoding="utf-8")
    assert "RotatingFileHandler" in tray, (
        "the tray no longer writes a rotating log file; remove the scope-out in the same change."
    )


def test_the_sandbox_worker_stderr_writer_is_filtered_not_disclosed() -> None:
    """§7's filter-coverage claim must match how the ADR 0087 child actually configures logging.

    The child inherits the engine's stderr (``stderr=None``) either way, so what decides the doc is
    whether it builds its own **unfiltered** handler. It used to: a bare ``basicConfig``, whose handler
    carries no filters, put WARNING+ records from admin-authored Handler code onto stream 1's own sink
    outside the chain, and §7 disclosed that. It now calls ``configure_stderr_logging``, which installs
    the same three filters (BACKLOG #1054), so the disclosure must be gone instead.

    Pinned BOTH ways, because the interesting direction is the regression: a future edit that put
    ``basicConfig`` back would silently reopen the gap, and this reddens and demands §7 say so again.
    """
    from messagefoundry.config.settings import ServiceSettings

    worker = (_ROOT / "messagefoundry" / "pipeline" / "_sandbox_worker.py").read_text(
        encoding="utf-8"
    )
    sandbox = (_ROOT / "messagefoundry" / "pipeline" / "sandbox.py").read_text(encoding="utf-8")
    assert "stderr=None" in sandbox, "the child no longer inherits the engine's stderr; revisit §7"
    unfiltered = "logging.basicConfig" in worker
    text = _doc_text()
    disclosed = "outside the filter chain" in text
    if unfiltered:
        assert disclosed, (
            "the sandbox worker child writes to the engine's INHERITED stderr through a bare "
            "basicConfig, so §7's 'three filters on every record' claim is not true of it. Say so."
        )
        assert "in the engine process" in text, (
            "the filter-coverage sentence must be scoped to the engine process"
        )
    else:
        assert not disclosed, (
            "the sandbox child installs the filter chain itself; §7 must not still disclose it as a "
            "writer outside the chain — an exclusion that no longer exists reads as an open weakness"
        )
        assert "configure_stderr_logging" in worker, (
            "the child neither uses basicConfig nor configure_stderr_logging — it may have no filter "
            "chain at all. Establish which, and say so in §7."
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


def test_every_socket_listener_that_emits_nothing_is_named_in_row_7() -> None:
    """Row 7 states which listeners this stream actually covers — derive that, don't trust the prose.

    RULE (16.1.1): the row presents itself as the coverage statement for the connection-event stream,
    so a socket listener that emits **no** event must be named as an exception. Nothing derived that:
    the row said the DICOM C-STORE SCP was the only silent listener while the ``ISA``/``IEA``-framed
    X12 inbound was equally silent, so an operator reading it concluded an X12 feed's connects and
    refusals were captured. They are not — ``transports/x12.py`` contains zero ``_emit_event`` calls,
    and its ``max_connections`` refusal writes no log either.

    Scoped to modules that actually call ``asyncio.start_server``: a poll/file source legitimately
    never emits (``SourceConnector.on_connection_event`` defaults to ``None`` precisely so those stay
    byte-identical), so including them would assert something untrue.
    """
    transports = _ROOT / "messagefoundry" / "transports"
    listeners: dict[str, bool] = {}
    for path in sorted(transports.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "asyncio.start_server" not in text:
            continue
        listeners[path.stem] = "_emit_event(" in text
    assert listeners, "no asyncio.start_server listener found — the walk broke, not the doc"
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
