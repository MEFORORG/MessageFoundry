# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Drift guards for the off-loopback runbook: its CLI invocations and its TOML config blocks.

Two independent classes of copy-paste defect, both of which have actually shipped in this document:

1. **CLI drift** (ASVS 16.4.2 section) — see the module body below.
2. **TOML drift** — the runbook's fenced ``toml`` blocks are meant to be copy-pasted into
   ``messagefoundry.toml``. Two of them silently rotted past an ADR 0118
   (``0118-secure-by-default-security-configuration-section.md``) key relocation and **aborted at
   config load** (``[diagnostics].audit_all_authz``, ``[ai].data_class``), so an operator following the
   runbook verbatim got an immediate start failure. ``test_every_runbook_toml_block_loads`` runs
   every block through the real ``load_settings`` and additionally fails on a **silently ignored**
   key — an unrecognized key only warns, so "it loads" alone would not have caught a misspelling
   that leaves the posture it was meant to set switched off.
3. **connections.toml drift** — the runbook also prints ``[[inbound]]`` blocks for the *other*
   copy-pasteable TOML file (ADR 0007). Those go through a different loader with a different (strict,
   unknown-key-rejecting) contract, so they are marked with a leading ``# connections.toml`` comment
   and guarded by ``test_every_runbook_connections_toml_block_loads`` instead.

The runbook's ``## Tamper-evident audit chain (ASVS 16.4.2)`` section prints a copy-pasteable
``messagefoundry <subcommand>`` command an operator runs to key an existing keyless audit chain. It
once printed the *store-method* name (``rekey_audit_chain``) rather than the *CLI subcommand*
(``rekey-audit``); argparse rejects the method name as an "invalid choice", so an operator following
the runbook verbatim got an error. This module pins the runbook command to the real CLI registry so
that class of defect can't drift back in:

* the ``messagefoundry <cmd>`` invocation in the 16.4.2 section names a **registered** subcommand
  (checked against the authoritative dispatch table in :mod:`messagefoundry.__main__`); and
* the store-method name ``rekey_audit_chain`` is **not** presented anywhere as a CLI command.

Structural assertion over the Markdown runbook + the CLI registry — no engine behaviour is exercised.
"""

from __future__ import annotations

import logging
import re
import warnings
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "security" / "OFF-LOOPBACK-DEPLOYMENT.md"

if not _DOC.exists():
    # ``docs/security/**`` is deny-listed from the OSS mirror (and vaulted after the cutover), so the
    # runbook this module asserts against is simply absent there. Without this guard the module raises
    # FileNotFoundError at IMPORT time, which is a hard collection ERROR that reds the whole required
    # test leg — exactly what happened on the mirror's first run of this file (added 2026-07-20).
    # Skipping is honest here, unlike a leak guard that silently stops guarding: there is no document
    # present to drift, so the assertion has nothing to say. See tests/test_anon_parity.py for the same
    # pattern over the deny-listed scanner.
    pytest.skip(
        "docs/security/OFF-LOOPBACK-DEPLOYMENT.md is private-only (OSS-mirror deny-list / vault)",
        allow_module_level=True,
    )

_SECTION_HEADING = "## Tamper-evident audit chain (ASVS 16.4.2)"
# The store METHOD name (store/store.py), which is NOT a CLI subcommand — must never appear as a command.
_STORE_METHOD_NAME = "rekey_audit_chain"
# The correct registered subcommand the section must instruct.
_EXPECTED_SUBCOMMAND = "rekey-audit"

# A fenced code block: ```<info>\n ... \n``` (the info string, e.g. ``toml``/``python``, is discarded).
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _audit_section() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.find(_SECTION_HEADING)
    assert start != -1, f"runbook section {_SECTION_HEADING!r} missing from {_DOC.name}"
    nxt = text.find("\n## ", start + len(_SECTION_HEADING))
    return text[start:] if nxt == -1 else text[start:nxt]


def _cli_invocations(section: str) -> list[str]:
    """Every ``messagefoundry <...>`` command line found inside a fenced block of ``section``."""
    invocations: list[str] = []
    for block in _FENCE_RE.finditer(section):
        for line in block.group(1).splitlines():
            stripped = line.strip()
            if stripped.startswith("messagefoundry "):
                invocations.append(stripped)
    return invocations


def test_runbook_audit_command_names_a_registered_cli_subcommand() -> None:
    # The dispatch table is the authoritative CLI registry — its keys are exactly the sub.add_parser(...)
    # names, and main() KeyErrors on any command not in it. Imported locally so a heavy-import failure is
    # contained to this test.
    from messagefoundry.__main__ import _DISPATCH

    invocations = _cli_invocations(_audit_section())
    assert invocations, f"no `messagefoundry <cmd>` fenced command found under {_SECTION_HEADING!r}"
    subcommands = [cmd.split()[1] for cmd in invocations]
    for cmd, sub in zip(invocations, subcommands, strict=True):
        assert sub in _DISPATCH, (
            f"runbook prints `{cmd}` but {sub!r} is not a registered CLI subcommand "
            f"(messagefoundry/__main__.py _DISPATCH / sub.add_parser). Registered: {sorted(_DISPATCH)}"
        )
    # The section exists to instruct the audit-rekey migration; that subcommand must be the one present.
    assert _EXPECTED_SUBCOMMAND in subcommands, (
        f"the 16.4.2 section must instruct `messagefoundry {_EXPECTED_SUBCOMMAND}`; "
        f"found instead: {subcommands}"
    )


def test_runbook_does_not_present_store_method_name_as_a_cli_command() -> None:
    # `rekey_audit_chain` is the store method, not a CLI subcommand; argparse rejects it as an invalid
    # choice. Guard the whole doc against the method name drifting back into a copy-pasteable command.
    text = _DOC.read_text(encoding="utf-8")
    assert f"messagefoundry {_STORE_METHOD_NAME}" not in text, (
        f"the runbook presents the store-method name `{_STORE_METHOD_NAME}` as a CLI command; "
        f"the registered subcommand is `{_EXPECTED_SUBCOMMAND}`"
    )
    for cmd in _cli_invocations(_audit_section()):
        assert _STORE_METHOD_NAME not in cmd, (
            f"store-method name leaked into a CLI invocation: {cmd!r}"
        )


# ── TOML config blocks: every fenced ``toml`` block must be copy-pasteable ────────────────────────

# ```toml\n ... \n``` with the block's 1-based start line, so a failure names the line to fix. The
# optional leading indent matters: a fence nested inside a numbered step is indented to stay part of
# that list item, and a column-0-only pattern would silently skip it — an unguarded block is exactly
# the defect class this module exists to stop. The closing fence must carry the SAME indent, so a
# nested fence can't swallow the rest of the document.
_TOML_FENCE_RE = re.compile(
    r"^(?P<indent>[ ]{0,6})```toml[ \t]*$\n(?P<body>.*?)^(?P=indent)```[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


def _dedent(body: str, indent: str) -> str:
    """Strip the fence's own list indent from each line, so the guard loads what a reader copies."""
    if not indent:
        return body
    return "".join(
        line.removeprefix(indent) if line.strip() else line
        for line in body.splitlines(keepends=True)
    )


#: A ``toml`` fence whose first non-blank line is this marker is a **connections.toml** block, not a
#: ``messagefoundry.toml`` one — different file, different loader, different (strict) key contract.
_CONNECTIONS_MARKER = "# connections.toml"


def _all_toml_fences() -> list[tuple[int, str]]:
    text = _DOC.read_text(encoding="utf-8")
    fences: list[tuple[int, str]] = []
    for match in _TOML_FENCE_RE.finditer(text):
        lineno = text.count("\n", 0, match.start()) + 2  # first line INSIDE the fence
        fences.append((lineno, _dedent(match.group("body"), match.group("indent"))))
    return fences


def _is_connections_block(body: str) -> bool:
    first = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    return first == _CONNECTIONS_MARKER


def _toml_blocks() -> list[tuple[int, str]]:
    """The service-settings (``messagefoundry.toml``) fences."""
    return [(n, b) for n, b in _all_toml_fences() if not _is_connections_block(b)]


def _connections_toml_blocks() -> list[tuple[int, str]]:
    """The connection-wiring (``connections.toml``, ADR 0007) fences."""
    return [(n, b) for n, b in _all_toml_fences() if _is_connections_block(b)]


@pytest.mark.parametrize(
    "lineno, body", _toml_blocks(), ids=lambda v: v if isinstance(v, int) else ""
)
def test_every_runbook_toml_block_loads(
    lineno: int, body: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Each fenced ``toml`` block loads, and no key in it is silently ignored.

    ``environ={}`` so the result is the block's own content, never the developer's ``MEFOR_*``. The
    ignored-key half matters as much as the load half: an unrecognized ``[section]`` key only
    *warns*, so a relocated or misspelled switch loads clean and leaves the posture it was meant to
    arm switched OFF — the failure mode this runbook can least afford.

    That half is captured from **stdlib logging**, which is where the loader actually emits it
    (``_log.warning("[security] has unrecognized key(s): ...")`` in ``config/settings.py``). An
    earlier revision of this test watched only ``warnings.catch_warnings``; the loader calls
    ``warnings.warn`` nowhere, so the assertion could never fire. The ``warnings`` capture is kept
    alongside it so a future ``warnings.warn``-based emitter is caught too.
    """
    from messagefoundry.config.settings import load_settings

    path = tmp_path / "messagefoundry.toml"
    path.write_text(body, encoding="utf-8")
    with caplog.at_level(logging.WARNING), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_settings(config_path=path, environ={})
    ignored = [
        message
        for message in (
            [str(w.message) for w in caught] + [rec.getMessage() for rec in caplog.records]
        )
        if "unrecognized" in message.lower()
    ]
    assert not ignored, (
        f"OFF-LOOPBACK-DEPLOYMENT.md toml block at line {lineno} has key(s) the engine IGNORES, so "
        f"the posture it documents is not in effect: {ignored}"
    )


@pytest.mark.parametrize(
    "lineno, body", _connections_toml_blocks(), ids=lambda v: v if isinstance(v, int) else ""
)
def test_every_runbook_connections_toml_block_loads(lineno: int, body: str, tmp_path: Path) -> None:
    """Each ``# connections.toml``-marked fence wires through the real ADR 0007 loader.

    Same copy-paste contract as the service-settings blocks, but a different failure mode is possible
    here: ``load_connections_file`` REJECTS an unknown key rather than ignoring it, so a stale key in
    the runbook is an immediate ``WiringError`` for the operator rather than a silent no-op. Running
    the block proves the transport/settings shape it prints is still buildable.
    """
    from messagefoundry.config.connections_file import load_connections_file
    from messagefoundry.config.wiring import Registry

    path = tmp_path / "connections.toml"
    path.write_text(body, encoding="utf-8")
    registry = Registry()
    load_connections_file(path, registry)
    assert registry.inbound or registry.outbound, (
        f"OFF-LOOPBACK-DEPLOYMENT.md connections.toml block at line {lineno} declared no connection"
    )


def test_runbook_engine_config_block_declares_in_use_data_protection(
    tmp_path: Path,
) -> None:
    """The runbook's own engine block must carry the ADR 0152 row-12 declaration.

    That block declares ``[api].tls_terminated_upstream``, which the engine counts as **exposed**, so
    on a PHI instance it is subject to ASVS 11.7.1 row 12. The published block would still *boot*
    without it (row 12 warns; it refuses only behind
    ``[security].require_memory_encryption_declaration``) — but this is the reference config for a
    deployment that is meant to be running on a host which provides the property, so it has to say so
    rather than ship a permanent warning.
    """
    from messagefoundry.config.settings import load_settings

    text = _DOC.read_text(encoding="utf-8")
    heading = "### The engine config beside either proxy"
    start = text.find(heading)
    assert start != -1, f"runbook section {heading!r} missing from {_DOC.name}"
    match = _TOML_FENCE_RE.search(text, start)
    assert match is not None, f"no toml block under {heading!r}"

    path = tmp_path / "messagefoundry.toml"
    path.write_text(_dedent(match.group("body"), match.group("indent")), encoding="utf-8")
    settings = load_settings(config_path=path, environ={})
    assert settings.security.memory_encryption_operator_declared is True, (
        "the runbook's engine config block declares [api].tls_terminated_upstream (exposed) but not "
        "[security].memory_encryption_operator_declared — an exposed PHI instance using it verbatim "
        "warns about missing in-use data protection on every start (ladder row 12, ADR 0152)"
    )


# ── the numbered operator steps: EXECUTABLE, and honestly bounded ────────────────────────────────
#
# The runbook's own score depends on operator actions the engine cannot take (per-feed strict HL7
# validation, retiring the bootstrap admin, directory ACLs, federation). They were absent for long
# enough that an assessment recorded "following the runbook in full is not sufficient". Prose is not
# enough to fix that: a step an operator cannot *execute* is the same gap with better wording. These
# guards pin that each prescribed step stays a numbered procedure with a stated consequence, and that
# the two DELIBERATELY-absent steps stay visibly absent rather than drifting into vague guidance.

_STEPS_HEADING = "## Operator steps this posture depends on"
_UNPRESCRIBED_HEADING = "### Steps not yet prescribed"
#: Each prescribed step, keyed by its number, with a token that must appear in its heading.
_PRESCRIBED_STEPS = {
    1: "Strict HL7 validation",
    2: "Retire the bootstrap Administrator",
    3: "Filesystem ACLs",
    4: "Federated sign-in",
}
_NUMBERED_ITEM_RE = re.compile(r"^\d+\. ", re.MULTILINE)


def _steps_section() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.find(_STEPS_HEADING)
    assert start != -1, f"runbook section {_STEPS_HEADING!r} missing from {_DOC.name}"
    nxt = text.find("\n## ", start + len(_STEPS_HEADING))
    return text[start:] if nxt == -1 else text[start:nxt]


def _step_bodies() -> dict[int, str]:
    """``{step number: that step's text}`` for every ``### Step N — ...`` heading in the section.

    Bounded by the next ``### `` heading of ANY kind, so the trailing not-yet-prescribed section is
    never counted as part of the last step's instructions.
    """
    section = _steps_section()
    heads = list(re.finditer(r"^### (?P<title>.+)$", section, re.MULTILINE))
    bodies: dict[int, str] = {}
    for index, match in enumerate(heads):
        numbered = re.match(r"Step (\d+) — ", match.group("title"))
        if numbered is None:
            continue
        end = heads[index + 1].start() if index + 1 < len(heads) else len(section)
        bodies[int(numbered.group(1))] = section[match.start() : end]
    return bodies


def test_runbook_prescribes_every_ownerless_operator_step() -> None:
    bodies = _step_bodies()
    assert sorted(bodies) == sorted(_PRESCRIBED_STEPS), (
        f"the operator-steps section must number the steps {sorted(_PRESCRIBED_STEPS)} contiguously; "
        f"found {sorted(bodies)}"
    )
    for number, token in _PRESCRIBED_STEPS.items():
        heading = bodies[number].splitlines()[0]
        assert token in heading, f"step {number}'s heading {heading!r} no longer names {token!r}"


@pytest.mark.parametrize("number", sorted(_PRESCRIBED_STEPS))
def test_each_operator_step_is_executable_and_states_its_consequence(number: int) -> None:
    body = _step_bodies()[number]
    items = _NUMBERED_ITEM_RE.findall(body)
    assert len(items) >= 3, (
        f"step {number} has {len(items)} numbered instruction(s) — a step the operator cannot execute "
        f"is the same gap the assessment recorded, with better wording"
    )
    assert "**Skip it and:**" in body, (
        f"step {number} does not state what is true if the operator skips it; the consequence is what "
        f"makes an optional-looking step get done"
    )


def test_the_two_owner_gated_steps_stay_visibly_unprescribed() -> None:
    """Absent-by-decision must read as absent — never as guidance a reader could act on."""
    section = _steps_section()
    start = section.find(_UNPRESCRIBED_HEADING)
    assert start != -1, (
        f"{_UNPRESCRIBED_HEADING!r} is missing: the AV/ICAP (5.4.3) and in-engine-TLS "
        f"(12.3.3/12.3.5) steps are deliberately not prescribed and must SAY so, or their absence "
        f"reads as an oversight"
    )
    body = section[start:]
    for token in ("ICAP", "5.4.3", "tls_cert_file", "12.3.3"):
        assert token in body, f"the not-yet-prescribed section no longer names {token!r}"
    assert not _NUMBERED_ITEM_RE.findall(body), (
        "the not-yet-prescribed section carries a numbered procedure — a placeholder that looks like "
        "an instruction is worse than no instruction"
    )
    # And the steps section must point at it, so a reader working top-to-bottom cannot miss it.
    assert "#steps-not-yet-prescribed" in section[:start], (
        "the operator-steps preamble no longer links to the not-yet-prescribed section"
    )
