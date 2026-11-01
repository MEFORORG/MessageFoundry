# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dialling CA check follow-ups (vault BACKLOG #3224), from the round 4 and 5 review of engine PR 2108.

Item 1: a DR activation that a trust anchor refuses answers and records a fixed line. The refusal's
own text names the CA's path, the folders above it and its SHA-256, so it goes to the server log
only.

Item 5: a ``tls_ca_pin`` setting the lane check refuses is reported as a setting to fix, not a file.
A kept CA failure whose settings stop resolving says so in the log.

Item 6: the two tests the review found missing, on the inbound arm of the connection test's CA
check and on the ``deployed`` and ``auto_start`` compares of a kept CA failure.

Each test names the single mutation it goes red under.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry.auth.trust_anchors as ta
from messagefoundry.api import create_app
from messagefoundry.api.app import _ANCHOR_REFUSED_DETAIL, _run_connection_test
from messagefoundry.auth.trust_anchors import (
    AnchorSettingRefused,
    AnchorStoreUnavailable,
    TrustAnchorError,
    trust_anchor_cause,
)
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.config.wiring import (
    Ftp,
    Registry,
    WiringError,
    build_inbound_connection,
    env,
)
from messagefoundry.pipeline import Engine, wiring_runner
from messagefoundry.pipeline.dr import DrActivationError
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from tests.test_dr_outlive_deadline import _admin_client, _coordinator, _rows, _seed
from tests.test_dr_passive_followups import _PASSIVE_UNCHECKED, _runner
from tests.test_outbound_ca_anchors import (
    _ca,
    _CountingSink,
    _outbound_registry,
    _real_ca,
    _sha,
)
from tests.test_trust_anchors import _block, _FaultyAuditStore, _path_ok

_IB = "IB_FTPS"
_PIN_MISMATCH = "does not match its configured SHA-256 pin"
#: What a step-4 abort says in place of the refusal's own text, when the refusal names no setting.
_ABORT_LINE = "a trust anchor was refused; the server log says which one and why"
#: What it says when the refusal names its setting (vault BACKLOG #3498).
_NAMED_ABORT_LINE = f"a trust anchor was refused (inbound connection '{_IB}' tls_ca_file)"
#: A pin no file here has, so the lane check refuses the CA.
_WRONG_PIN = "00" * 32


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only the pin."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "followups.db")
    yield s
    await s.close()


def _poller_graph(
    ca: Path, pin: Any, *, deployed: bool = True, auto_start: bool = True, name: str = _IB
) -> Registry:
    """One critical inbound ``Ftp`` poller over FTPS, on a dead loopback port and routed nowhere.
    It is the one inbound that dials out, so the runner checks its CA lane by lane."""
    reg = Registry()
    spec = Ftp(
        host="127.0.0.1",
        port=9,
        tls=True,
        remote_dir="/out",
        tls_ca_file=str(ca),
        tls_ca_pin=pin,
    )
    reg.add_inbound(
        build_inbound_connection(
            name,
            spec,
            router="r",
            priority=Priority.CRITICAL,
            deployed=deployed,
            auto_start=auto_start,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


# --- item 1: a refused DR activation names no CA path -------------------------------------


@pytest.fixture
async def dr_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """A passive DR standby with the two CA checks ``serve`` hands an engine. Its store is
    encrypted and carries a cold-seed archive of itself, so an activation clears its gates."""
    store, archive, ss = await _seed(tmp_path)
    engine = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, activate=False, seed_archive=archive),
        egress_settings=EgressSettings(deny_by_default=False),
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
    )
    # The seed holds a row for a destination this graph does not declare.
    await store.dead_letter_missing_destinations(set())
    yield engine
    await engine.stop()


#: The folder the short CA path names. A word no abort line holds, so finding it is a leak.
_CA_DIR = "anchors3224"


def _short_ca(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A CA named by a short relative path, with the working directory moved under it.

    The length matters. ``safe_exc`` keeps 200 characters and drops a token that crosses that
    mark, so the long path of a pytest temp folder never reached the old abort line, and a test
    using one passes against the unfixed code. A path of an ordinary length did reach it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / _CA_DIR).mkdir()
    return _ca(tmp_path / _CA_DIR).relative_to(tmp_path)


def _leaks(ca: Path, text: str) -> list[str]:
    """The parts of the CA's path found in ``text``: its file name and its folder. Neither
    needle holds a path separator, since a quoted Windows path doubles each one."""
    return [part for part in (ca.name, ca.parent.name) if part in text]


async def test_a_dr_activation_a_poller_ca_refuses_answers_and_records_no_path(
    dr_engine: Engine,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reload's lane check refuses the poller's CA, which refuses the activation, and the
    route answers 503. Red under: step 4 of ``DrCoordinator._activate_locked`` taking
    ``safe_exc(exc)`` for every error, as it did before.

    The line names the connection and its setting, and still no part of the path (vault
    BACKLOG #3498). Red under: step 4 taking the unnamed line for every refusal."""
    ca = _short_ca(tmp_path, monkeypatch)
    dr_engine.add_registry(_poller_graph(ca, _WRONG_PIN))
    await dr_engine.start()
    client, _app = await _admin_client(dr_engine, deadline=30.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr"):
        async with client:
            answer = await client.post("/dr/activate", json={})

    assert answer.status_code == 503
    detail = str(answer.json()["detail"])
    (row,) = await _rows(dr_engine.store, "dr_activation_aborted")
    assert row["kind"] == "profile"
    for text in (detail, str(row["reason"])):
        assert _leaks(ca, text) == [], text
        assert _NAMED_ABORT_LINE in text
        assert "could not bind the priority feeds" in text  # the reload refused, not the preflight
    # The control for the two zeros above: the same needles find the path in the server log,
    # which keeps the refusal's own text.
    logged = [r.getMessage() for r in caplog.records if r.name == "messagefoundry.pipeline.dr"]
    refusals = [line for line in logged if _PIN_MISMATCH in line]
    assert refusals and all(_leaks(ca, line) == [ca.name, _CA_DIR] for line in refusals), refusals
    assert dr_engine.dr_active is False


async def _refused_in_its_preflight(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refuse: Any
) -> tuple[DrActivationError, str]:
    """Activate a box whose registry preflight is ``refuse``. Returns what the abort leaves: the
    error the route answers with, and the audit row's reason."""
    ca = _ca(tmp_path)
    dr_engine.add_registry(_poller_graph(ca, _sha(ca)))
    await dr_engine.start()
    monkeypatch.setattr(dr_engine, "preflight_registry", refuse)
    with pytest.raises(DrActivationError) as caught:
        await _coordinator(dr_engine).activate(actor="alice")
    assert caught.value.kind == "profile"
    (row,) = await _rows(dr_engine.store, "dr_activation_aborted")
    return caught.value, str(row["reason"])


async def test_a_dr_activation_its_preflight_refuses_names_no_path(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other arm of step 4: the trust-anchor preflight refuses before any reload. The
    refusal is raised the way ``make_registry_anchor_preflight`` raises a listener's or a
    ``FhirLookup``'s. Red under the same mutation as the test above.

    The abort is raised outside the handler that caught the refusal, as the connection-start
    route raises its 409, so the refusal is not left on the abort for a later reader of the
    chain. Red under: the abort raised inside the handler."""
    named = Path(_CA_DIR) / "partner-ca.pem"

    async def refuse(_registry: object) -> None:
        error = ta.connection_anchor_failure(
            TrustAnchorError(f"the trust anchor '{named.as_posix()}' {_PIN_MISMATCH}")
        )
        raise error from error.__cause__

    abort, reason = await _refused_in_its_preflight(dr_engine, tmp_path, monkeypatch, refuse)
    for text in (str(abort), reason):
        assert _leaks(named, text) == [], text
        assert _ABORT_LINE in text
        assert "stopped at its preflight" in text
    assert abort.__context__ is None and abort.__cause__ is None


async def test_a_dr_activation_refused_by_anything_else_keeps_its_own_text(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two above, and the limit of the repair: only a refusal a trust anchor
    caused loses its text. An error raised while one was being handled is not such a refusal, so
    it keeps its own. Red under: the chain walk following ``__context__``."""

    async def refuse(_registry: object) -> None:
        try:
            raise TrustAnchorError("a refusal that was handled")
        except TrustAnchorError:
            raise WiringError(f"a config value under {_CA_DIR} is not readable")  # noqa: B904

    abort, reason = await _refused_in_its_preflight(dr_engine, tmp_path, monkeypatch, refuse)
    for text in (str(abort), reason):
        assert f"a config value under {_CA_DIR} is not readable" in text
        assert _ABORT_LINE not in text
    assert isinstance(abort.__context__, WiringError)  # such an abort keeps what caused it


def test_the_chain_walk_follows_explicit_causes_only_and_ends_on_a_cycle() -> None:
    """``trust_anchor_cause`` on each shape step 4 can be handed. It is the one copy the DR
    abort and the API's routes share (vault BACKLOG #3498)."""
    refusal = TrustAnchorError("refused")
    assert trust_anchor_cause(refusal) is refusal
    wrapped = ta.connection_anchor_failure(refusal)
    assert wrapped.__cause__ is refusal and trust_anchor_cause(wrapped) is refusal
    # A blank pin is a ValueError, which the reload check wraps in a TrustAnchorError first.
    blank = ta.connection_anchor_failure(ValueError("a blank pin"), setting="a lane")
    assert (found := trust_anchor_cause(blank)) is not None and found.setting == "a lane"
    assert trust_anchor_cause(WiringError("a listener could not bind")) is None
    looped, other = RuntimeError("a"), RuntimeError("b")
    looped.__cause__, other.__cause__ = other, looped
    assert trust_anchor_cause(looped) is None


async def test_the_lane_check_names_the_setting_it_refused(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The lane check says which kind of refusal it raised, and names the setting with no path
    (vault BACKLOG #3498). A refused file carries its spec's setting, from the audited check and
    from the remembered repeat alike. A refused setting is an ``AnchorSettingRefused``. Red
    under: ``_preflight_one`` not setting ``setting``, the repeat not setting it, or the spec's
    ``ValueError`` raised bare."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    ca = _ca(tmp_path)
    settings = {"tls_ca_file": str(ca), "tls_ca_pin": _WRONG_PIN}
    for _ in range(2):  # the audited check, then the repeat it remembers
        with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH) as refused:
            await check("inbound", _IB, settings)
        assert refused.value.setting == f"inbound connection '{_IB}' tls_ca_file"
        assert ca.name in str(refused.value)  # the control: the refusal's own text has the file
    with pytest.raises(AnchorSettingRefused):
        await check("inbound", _IB, {**settings, "tls_ca_pin": " "})


async def test_the_lane_check_takes_a_path_the_os_refuses_as_a_setting(
    store: MessageStore,
) -> None:
    """A NUL in the CA path is a setting to fix: no file was read and no row written (vault
    BACKLOG #3498). Red under: the check letting the read's ``ValueError`` out bare."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(AnchorSettingRefused):
        await check("outbound", "OB_X", {"tls_ca_file": "bad\x00path.pem"})


async def test_a_pin_that_does_not_parse_names_the_pin(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A malformed pin, as an ``env()`` value can resolve to, is a setting the lane check refuses
    before any audit row is written. Its cause, ``evaluate_anchor``'s refusal, names the pin's
    setting, not the file's, as the audited check's does (vault BACKLOG #3498). Red under: the
    lane check letting that ``TrustAnchorError`` out bare, or ``evaluate_anchor`` raising it with
    no ``setting``."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    settings = {"tls_ca_file": str(_ca(tmp_path)), "tls_ca_pin": "zz"}
    with pytest.raises(AnchorSettingRefused) as refused:
        await check("outbound", "OB_X", settings)
    cause = refused.value.__cause__
    assert isinstance(cause, TrustAnchorError)
    assert cause.setting == "outbound connection 'OB_X' tls_ca_pin"
    assert await store.list_audit(action="auth.trust_anchor", limit=5) == []
    spec = ta.lane_anchor_spec("outbound", "OB_X", settings)
    assert spec is not None
    with pytest.raises(TrustAnchorError) as audited:
        await ta._preflight_one(store, spec, enforcing=True)
    assert audited.value.setting == "outbound connection 'OB_X' tls_ca_pin"


async def test_an_env_pin_that_does_not_parse_is_told_to_fix_the_setting(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """An ``env()`` pin that resolves but does not parse wrote no audit row, so its line is the
    setting's, not the file's, which names audit rows (vault BACKLOG #3498). Red under: the lane
    check letting ``evaluate_anchor``'s ``TrustAnchorError`` out bare."""
    reg = _poller_graph(_ca(tmp_path), env("ftps_ca_pin"))
    runner = _runner(store, reg, env_values={"ftps_ca_pin": "zz"})
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_pin or tls_ca_file setting was refused. Fix the setting" in reason
        assert _FIX_THE_FILE not in reason and "audit rows" not in reason
    finally:
        await runner.stop()


def test_a_dr_abort_names_a_long_connection_whole() -> None:
    """The longest connection name reaches the abort line whole (vault BACKLOG #3498). Red
    under: the setting cut at 120 characters, as it first was."""
    from messagefoundry.pipeline.dr import _anchor_refused

    setting = f"inbound connection 'IB_{'X' * 253}' tls_ca_file"
    assert f"({setting})" in _anchor_refused(setting)


@pytest.mark.parametrize(
    ("cause", "reason", "status"),
    [(AnchorStoreUnavailable, "store_unavailable", 503), (TrustAnchorError, "trust_anchor", 422)],
)
async def test_the_reload_route_reads_a_cause_below_the_first(
    store: MessageStore, cause: type[Exception], reason: str, status: int
) -> None:
    """A store fault or a refusal two ``WiringError`` wrappers down is still read as one: the
    store arm walks the explicit chain, and the anchor arm walks its ``WiringError`` links (vault
    BACKLOG #3498). Red under: either arm reading one level only."""
    from messagefoundry.api.app import _audit_refused_reload

    inner = WiringError("inner")
    inner.__cause__ = cause("x")
    outer = WiringError("outer")
    outer.__cause__ = inner
    engine = Engine(store, config_dir=None, egress_settings=EgressSettings())
    answered, _ = await _audit_refused_reload(
        engine, outer, actor="alice", requested=None, dry_run=False
    )
    rows = await store.list_audit(action="config_reload_failed", limit=5)
    assert answered == status
    assert [json.loads(r["detail"])["reason"] for r in rows] == [reason]


async def test_a_reload_with_a_typo_in_a_literal_pin_is_an_invalid_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo in a literal ``tls_ca_pin`` is refused by the factory as a ``ValueError``, whose own
    cause is ``parse_anchor_pin``'s ``TrustAnchorError``. That is a config to fix, audited
    ``invalid_config`` as before the chain walk; only the shape a trust-anchor check raises is
    ``trust_anchor`` (vault BACKLOG #3498). The control is a CA the registry preflight refuses,
    in the same route. Red under: the anchor arm walking the whole cause chain."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = tmp_path / "anchor.pem"
    ca.write_bytes(_block(b"ca"))
    out = str(tmp_path / "out")
    head = "from messagefoundry import MLLP, File, Rest, Send, handler, inbound, outbound, router\n"
    tail = (
        f"outbound('OUT', File(directory={out!r}))\n"
        "@router('r')\ndef route(msg):\n    return ['h']\n"
        "@handler('h')\ndef handle(msg):\n    return Send('OUT', msg)\n"
    )
    typo, refused = tmp_path / "typo", tmp_path / "refused"
    typo.mkdir()
    refused.mkdir()
    (typo / "feed.py").write_text(
        head + "inbound('ADT_IN', MLLP(port=21575), router='r')\n"
        f"outbound('OB_REST', Rest(url='https://example.test/x', tls_ca_file={str(ca)!r}, "
        f"tls_ca_pin={'3g' * 32!r}))\n" + tail,
        encoding="utf-8",
    )
    (refused / "feed.py").write_text(
        head + f"inbound('ADT_IN', MLLP(port=21575, tls=True, tls_cert_file={str(ca)!r}, "
        f"tls_ca_file={str(ca)!r}), router='r')\n" + tail,
        encoding="utf-8",
    )
    store = await MessageStore.open(tmp_path / "e.db")
    engine = Engine(
        store,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            reasons = []
            for target in (typo, refused):
                r = await client.post("/config/reload", json={"config_dir": str(target)})
                assert r.status_code == 422, r.text
                (row,) = await store.list_audit(action="config_reload_failed", limit=1)
                reasons.append(json.loads(row["detail"])["reason"])
        assert reasons == ["invalid_config", "trust_anchor"]
    finally:
        await engine.stop()  # closes the store too


# --- item 5: the advice a refused setting gets, and a kept failure that stops resolving --------


def _raising(exc: BaseException) -> Any:
    """A lane check that raises ``exc`` for every lane."""

    async def check(_direction: str, _name: str, _settings: object) -> None:
        raise exc

    return check


_FIX_THE_FILE = "Fix the file"


def _blank_pin_runner(store: MessageStore, tmp_path: Path, **kw: Any) -> RegistryRunner:
    """A poller whose ``tls_ca_pin`` is an ``env()`` value set to nothing. A blank literal
    refuses when the graph loads; this one reaches the lane check, which raises
    ``AnchorSettingRefused``."""
    reg = _poller_graph(_ca(tmp_path), env("ftps_ca_pin"))
    return _runner(store, reg, env_values={"ftps_ca_pin": ""}, **kw)


async def test_a_refused_pin_setting_is_not_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A blank pin is a setting to change, and a start reads the same setting again. Red under:
    ``_lane_anchor_fault`` not reading an ``AnchorSettingRefused`` as a setting."""
    runner = _blank_pin_runner(store, tmp_path)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert reason == (
            f"TrustAnchorError: inbound connection '{_IB}': its tls_ca_pin or tls_ca_file "
            "setting was refused. Fix the setting, then reload and start the connection; the "
            "server log says why"
        )
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


async def test_a_refused_file_is_still_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The control for the test above: a pin the file does not match is a refused file."""
    runner = _runner(store, _poller_graph(_ca(tmp_path), _WRONG_PIN))
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_file was refused. Fix the file, then start the connection" in reason
    finally:
        await runner.stop()


async def test_a_passive_standby_does_not_tell_a_refused_setting_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The passive start's own line. Red under: ``_lane_anchor_fault`` not reading an
    ``AnchorSettingRefused`` as a setting."""
    runner = _blank_pin_runner(store, tmp_path, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_pin or tls_ca_file setting was refused on this passive DR" in reason
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


async def test_a_passive_check_that_could_not_run_is_not_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path
) -> None:
    """Nothing read the file, so nothing says it is at fault. Red under: the could-not-be-checked
    arm of ``_preflight_passive_lanes`` given the refused file's advice again."""

    reg = _poller_graph(_ca(tmp_path), _WRONG_PIN)
    cannot_run = _raising(RuntimeError("the audit store did not answer"))
    runner = _runner(store, reg, lane_anchor_check=cannot_run, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert _PASSIVE_UNCHECKED in reason
        assert "reload once the cause is fixed" in reason
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


@pytest.mark.parametrize("passive", [False, True], ids=["start", "passive"])
async def test_only_the_check_says_a_setting_was_refused(
    store: MessageStore, tmp_path: Path, passive: bool
) -> None:
    """A ``WiringError`` is a ``ValueError`` too, and it used to take the setting's line. Only
    the check's own ``AnchorSettingRefused`` does now (vault BACKLOG #3498). Red under:
    ``_lane_anchor_fault`` reading any ``ValueError`` as a setting."""

    reg = _poller_graph(_ca(tmp_path), _WRONG_PIN)
    standby = {"dr_standby": Priority.CRITICAL} if passive else {}
    refuses = _raising(WiringError("a refusal that is no setting"))
    runner = _runner(store, reg, lane_anchor_check=refuses, **standby)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_file was refused" in reason and _FIX_THE_FILE in reason
        assert "setting was refused" not in reason
    finally:
        await runner.stop()


#: A connection name of an ordinary length that the old 200-character cut could not take whole,
#: and the longest name ``CONNECTION_NAME_PATTERN`` allows.
_LONG_NAMES = ["IB_REGIONAL_LAB_RESULTS_FTPS_POLL", "IB_" + "X" * 253]


@pytest.mark.parametrize("name", _LONG_NAMES, ids=["ordinary", "longest"])
@pytest.mark.parametrize(
    ("raised", "passive", "ending"),
    [
        (TrustAnchorError, False, "the auth.trust_anchor audit rows say why"),
        (AnchorSettingRefused, False, "and start the connection; the server log says why"),
        (AnchorStoreUnavailable, False, "once the store is back; the server log says why"),
        (TrustAnchorError, True, "the auth.trust_anchor audit rows say why"),
        (
            AnchorSettingRefused,
            True,
            "Fix the setting, then reload; the server log says why",
        ),
        (RuntimeError, True, "reload once the cause is fixed"),
    ],
    ids=["file", "setting", "store", "passive-file", "passive-setting", "passive-unchecked"],
)
async def test_a_lane_ca_line_is_kept_whole(
    store: MessageStore,
    tmp_path: Path,
    raised: type[Exception],
    passive: bool,
    ending: str,
    name: str,
) -> None:
    """Every fixed CA line reaches the lane's status whole, advice included, up to the longest
    connection name (vault BACKLOG #3498). ``safe_exc``'s 200 characters cut the passive lines
    for any name, and the store's line too. Red under: ``_record_failed`` taking ``safe_exc``'s
    default for a ``fixed_text`` line."""
    reg = _poller_graph(_ca(tmp_path), None, name=name)
    standby = {"dr_standby": Priority.CRITICAL} if passive else {}
    runner = _runner(store, reg, lane_anchor_check=_raising(raised("x")), **standby)
    await runner.start()
    try:
        reason = runner.inbound_failed(name) or ""
        assert reason.startswith(f"TrustAnchorError: inbound connection '{name}': its ")
        assert reason.endswith(ending) and len(reason) > 200, reason
    finally:
        await runner.stop()


#: The fixed answers for a check the store stopped, spelled here so a test fails if one goes.
_STORE_START = "the engine could not reach its store to check a trust anchor; see the engine log"
_STORE_RESTART = "so this restart left the connection stopped"


async def _control(engine: Engine, action: str) -> httpx.Response:
    """POST ``action`` for the poller. A 500 arrives as a response, not a raise."""
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.post(f"/connections/{_IB}/{action}")


@pytest.fixture
async def store_stopped_engine(
    store: MessageStore, tmp_path: Path, judged: None
) -> AsyncIterator[Engine]:
    """An engine over a working store whose poller's CA check meets a store refusing its audit
    read, the shape the real check raises. The lane reads ``failed`` from the first start."""
    faulty: Any = _FaultyAuditStore("list_audit")
    engine = Engine(
        store,
        lane_anchor_check=ta.make_lane_anchor_check(faulty, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_poller_graph(_ca(tmp_path), None))
    await engine.start()
    yield engine
    await engine.stop()


@pytest.mark.parametrize(
    ("action", "expected"), [("start", _STORE_START), ("restart", _STORE_RESTART)]
)
async def test_the_control_route_answers_a_stopped_check_as_a_store_fault(
    store_stopped_engine: Engine, store: MessageStore, action: str, expected: str
) -> None:
    """Vault BACKLOG #3746 item 1: a store that stops the CA check answers 503 with a store line,
    not the 409 "trust anchor refused" of a CA that was checked. A restart's stop half already ran,
    so its line says the connection is left stopped. The lane's status keeps its "could not be
    checked" line, and the refused row is still written. The refused CA keeps its 409 in
    ``test_the_control_route_audits_a_refused_poller_start``. Red under: the route's
    ``AnchorStoreUnavailable`` test removed from its ``TrustAnchorError`` arm, or the restart's
    line dropped."""
    r = await _control(store_stopped_engine, action)
    assert r.status_code == 503, r.text
    assert expected in r.json()["detail"]
    assert "refused" not in r.json()["detail"]
    rr = store_stopped_engine.registry_runner
    assert rr is not None and not rr.inbound_running(_IB)
    assert "could not be checked" in (rr.inbound_failed(_IB) or "")
    assert await _rows(store, "connection_control") == [
        {
            "connection": _IB,
            "action": action,
            "role": "source",
            "running": False,
            "reason": "store_unavailable",
        }
    ]


async def test_a_stopped_check_on_a_restart_leaves_a_running_poller_down(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """What the restart's line says, on a lane that was serving. The stop half runs before the
    check, so a store fault there takes the poller down, and the answer has to say so. Red under:
    ``restart_inbound`` checking first, which makes the line false, so it would have to change."""
    faulty: Any = _FaultyAuditStore(None)
    engine = Engine(
        store,
        lane_anchor_check=ta.make_lane_anchor_check(faulty, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_poller_graph(_real_ca(tmp_path), None))
    await engine.start()
    try:
        rr = engine.registry_runner
        assert rr is not None and rr.inbound_running(_IB)
        faulty.fail = "list_audit"
        r = await _control(engine, "restart")
        assert r.status_code == 503, r.text
        assert _STORE_RESTART in r.json()["detail"]
        assert not rr.inbound_running(_IB)
    finally:
        await engine.stop()


def _store_fault_line() -> TrustAnchorError:
    """What a start raises for a check the store stopped: the lane's fixed line, from the fault."""
    line = TrustAnchorError("inbound connection: its tls_ca_file could not be checked")
    line.__cause__ = AnchorStoreUnavailable("the store refused the trust-anchor audit read")
    return line


@pytest.mark.parametrize(
    ("action", "raised", "status", "detail"),
    [
        pytest.param("start", _store_fault_line(), 503, _STORE_START, id="store"),
        pytest.param("restart", _store_fault_line(), 503, _STORE_RESTART, id="store-restart"),
        pytest.param("start", TrustAnchorError("x"), 409, _ANCHOR_REFUSED_DETAIL, id="anchor"),
        pytest.param("start", WiringError("x"), 409, f"{_IB!r}: start refused", id="start-gate"),
    ],
)
async def test_a_refused_start_keeps_its_answer_when_its_audit_row_fails(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    action: str,
    raised: Exception,
    status: int,
    detail: str,
) -> None:
    """Vault BACKLOG #3746 item 1: a store that stopped the check is likely to refuse the refused
    start's own row, and the answer stands either way, on each arm that shares the write. The lost
    row is logged at ERROR. Red under: the shared block calling ``_record_control_audit``
    unguarded, which answers 500."""
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    engine.add_registry(_poller_graph(Path("unused.pem"), None, auto_start=False))
    await engine.start()
    rr = engine.registry_runner
    assert rr is not None
    real = store.record_audit

    async def refuse_start(_name: str, *, operator: bool) -> None:
        raise raised

    async def refuse_control(audit_action: str, **kwargs: Any) -> None:
        if audit_action == "connection_control":
            raise sqlite3.OperationalError("database is locked")
        await real(audit_action, **kwargs)

    monkeypatch.setattr(rr, f"{action}_inbound", refuse_start)
    monkeypatch.setattr(store, "record_audit", refuse_control)
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
            r = await _control(engine, action)
        assert r.status_code == status, r.text
        assert detail in r.json()["detail"]
        lost = [rec for rec in caplog.records if "connection_control row" in rec.getMessage()]
        assert [rec.levelno for rec in lost] == [logging.ERROR]
    finally:
        await engine.stop()


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
async def test_a_connection_test_reports_a_stopped_check_as_a_store_fault(
    store: MessageStore, tmp_path: Path, judged: None, direction: str
) -> None:
    """Vault BACKLOG #3746 item 2: the store's fault used to come back as "connector build failed:
    the store refused ...", which the route wrote to ``audit_log.detail``. It is the fixed store
    line now, naming no connection, label or backend type, and the runner raises it as the store
    refusal, not as a failed build. Red under: ``check_test_anchor``'s store arm removed, or the
    route's."""
    ca = _ca(tmp_path)
    reg, name = _poller_graph(ca, None), _IB
    if direction == "outbound":
        reg, name = _outbound_registry(ca, _sha(ca)), "OUT"
    faulty: Any = _FaultyAuditStore("list_audit")
    check = ta.make_lane_anchor_check(faulty, enforcing=True)
    runner = _runner(store, reg, lane_anchor_check=check)
    result = await _run_connection_test(runner, name, direction)
    assert (result.supported, result.success) == (True, False)
    assert result.detail == _STORE_START
    with pytest.raises(WiringError, match="a trust anchor could not be checked") as err:
        await runner.check_test_anchor(name)
    assert isinstance(err.value.__cause__, AnchorStoreUnavailable)


@pytest.mark.parametrize("row_lands", [True, False], ids=["row-written", "row-lost"])
async def test_the_connection_test_route_keeps_the_store_line_when_its_row_fails(
    store: MessageStore,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    row_lands: bool,
) -> None:
    """Vault BACKLOG #3746 item 2, through the route: the fixed line reaches the caller, and
    ``audit_log.detail`` when the row lands. A store that stopped the check is likely to refuse
    this row too, and the line stands then as well. Red under: the route's write left bare, which
    answers 500 for ``row-lost``."""
    faulty: Any = _FaultyAuditStore("list_audit")
    engine = Engine(
        store,
        lane_anchor_check=ta.make_lane_anchor_check(faulty, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_poller_graph(_ca(tmp_path), None, auto_start=False))
    await engine.start()
    real = store.record_audit

    async def refuse_test_row(action: str, **kwargs: Any) -> None:
        if action == "connection_test":
            raise sqlite3.OperationalError("database is locked")
        await real(action, **kwargs)

    if not row_lands:
        monkeypatch.setattr(store, "record_audit", refuse_test_row)
    try:
        r = await _control(engine, "test")
        assert r.status_code == 200, r.text
        assert (r.json()["success"], r.json()["detail"]) == (False, _STORE_START)
        rows = await _rows(store, "connection_test")
        assert [row["detail"] for row in rows] == ([_STORE_START] if row_lands else [])
    finally:
        await engine.stop()


async def test_a_connection_test_still_reports_a_failed_build_as_one(store: MessageStore) -> None:
    """The control for the test above: a lane check's other faults keep the build failure's text,
    so the store arm did not swallow them. Red under: the store arm catching ``Exception``."""
    reg = _poller_graph(Path("unused.pem"), None)
    runner = _runner(store, reg, lane_anchor_check=_raising(RuntimeError("a lane check bug")))
    result = await _run_connection_test(runner, _IB, "inbound")
    assert result.detail == "connector build failed: a lane check bug"


async def test_a_kept_failure_whose_settings_stop_resolving_says_so_in_the_log(
    store: MessageStore,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The kept failure is not compared, and that used to happen with no line saying so. The
    arm is a backstop, so the test calls it directly. Red under: the ``log.info`` call lowered
    to ``log.debug``, which leaves no line at INFO."""
    reg = _poller_graph(_ca(tmp_path), _WRONG_PIN)
    runner = _runner(store, reg)
    await runner.start()
    try:
        poller = reg.inbound[_IB]
        assert runner._keeps_anchor_failure("inbound", _IB, reg, poller)  # the control: kept

        def unresolved(_conn: object) -> None:
            raise WiringError("env('ftps_ca_pin') is not set in this environment")

        monkeypatch.setattr(runner, "_anchor_lane_settings", unresolved)
        with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.wiring_runner"):
            assert not runner._keeps_anchor_failure("inbound", _IB, reg, poller)
        lines = [r.getMessage() for r in caplog.records if "no longer resolve" in r.getMessage()]
        assert len(lines) == 1 and _IB in lines[0] and "ftps_ca_pin" in lines[0], lines
    finally:
        await runner.stop()


# --- item 6: the two tests the review found missing -----------------------------------------


async def test_a_connection_test_of_a_failed_poller_does_not_let_the_next_reload_skip_its_ca(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inbound arm of ``check_test_anchor``. The poller fails its start for a reason that is
    not its CA, so it is recorded failed and not marked. Its CA is then swapped. A connection
    test checks it and must not mark it, or the next reload would keep the failure and skip the
    check. The outbound arm has this test in ``tests/test_outbound_ca_anchors.py``. Red under:
    ``fails_lane=False`` dropped from the inbound call in ``check_test_anchor``."""
    from messagefoundry.transports import build_source as real

    calls = 0

    def flaky(cfg: Any, **kw: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("partner endpoint not ready")
        return real(cfg, **kw)

    monkeypatch.setattr(wiring_runner, "build_source", flaky)
    ca = _ca(tmp_path)
    runner = _runner(store, _poller_graph(ca, _sha(ca)))
    await runner.start()
    try:
        assert "partner endpoint not ready" in (runner.inbound_failed(_IB) or "")
        ca.write_bytes(_block(b"substitute"))
        result = await _run_connection_test(runner, _IB, "inbound")
        assert result.success is False and result.detail == _ANCHOR_REFUSED_DETAIL
        for _ in range(2):
            with pytest.raises(WiringError, match=_PIN_MISMATCH):
                await runner.reload()
    finally:
        await runner.stop()


@pytest.mark.parametrize("flag", ["deployed", "auto_start"])
async def test_flipping_a_flag_back_ends_a_kept_ca_failure(
    store: MessageStore, tmp_path: Path, judged: None, flag: str
) -> None:
    """``_keeps_anchor_failure`` compares ``deployed`` and ``auto_start`` as well as the spec. A
    poller its CA failed is taken down by one flag and put back with no other change. The reload
    that puts it back builds it, so it reads the CA and refuses on the one still refused. Red
    under: that flag's compare removed from ``_keeps_anchor_failure``, one flag per case.

    It needs an inbound. A reload that takes an outbound down drops its failed record, which ends
    the kept failure before either compare is asked."""
    ca = _ca(tmp_path)
    up = _poller_graph(ca, _WRONG_PIN)
    sink = _CountingSink()
    runner = _runner(store, up, alert_sink=sink)
    await runner.start()
    try:
        assert sink.stopped == [_IB]
        await runner.reload(up)  # the control: with nothing changed the failure is kept
        down = _poller_graph(
            ca, _WRONG_PIN, deployed=flag != "deployed", auto_start=flag != "auto_start"
        )
        await runner.reload(down)
        assert runner.inbound_failed(_IB) is not None  # still recorded, so only the flag differs
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await runner.reload(_poller_graph(ca, _WRONG_PIN))
    finally:
        await runner.stop()
