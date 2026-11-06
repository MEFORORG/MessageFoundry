# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The lane CA check's reads and memory (vault BACKLOG #3188, from engine PR 2108's review).

Item 1: one read of the CA per check, and the verdict judged is the one that read found.
Item 2: a repeat of the last clean pass is not judged again, a pass that wrote a violation row
is judged and writes it at every check, and a changed file, ACL result or setting is judged
again. Item 3: a reload that removes or renames a lane drops the lane's refusal mark and the
check's memory of it.

Each test names the mutation it goes red under.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.auth.trust_anchors as ta
from messagefoundry.auth.anchor_path import ChainFinding, PathVerdict
from messagefoundry.auth.trust_anchors import RetainsLanes, TrustAnchorError
from messagefoundry.config.wiring import Registry, Rest, build_outbound_connection
from messagefoundry.store import MessageStore
from tests.test_outbound_ca_anchors import _ca, _outbound_registry, _rows, _runner, _sha
from tests.test_trust_anchors import _block, _path_ok

_PIN_MISMATCH = "does not match its configured SHA-256 pin"
_OUT = "OUT"
_LABEL = f"outbound:{_OUT}"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "memo.db")
    yield s
    await s.close()


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only what it is about."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _settings(ca: Path, pin: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"tls_ca_file": str(ca)}
    if pin is not None:
        out["tls_ca_pin"] = pin
    return out


def _count_reads(monkeypatch: pytest.MonkeyPatch, after: Any = None) -> list[int]:
    """Count each ``evaluate_anchor`` call. ``after``, when given, runs after the first read."""
    calls = [0]
    real = ta.evaluate_anchor

    def counted(spec: ta.AnchorSpec) -> ta.AnchorVerdict:
        verdict = real(spec)
        calls[0] += 1
        if calls[0] == 1 and after is not None:
            after()
        return verdict

    monkeypatch.setattr(ta, "evaluate_anchor", counted)
    return calls


def _count_judgments(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    real = ta._preflight_one

    async def counted(*args: Any, **kw: Any) -> str:
        calls[0] += 1
        return await real(*args, **kw)

    monkeypatch.setattr(ta, "_preflight_one", counted)
    return calls


# --- item 1: one read per check ----------------------------------------------------------------


@pytest.mark.parametrize("refused", [False, True])
async def test_a_check_reads_the_ca_once(
    store: MessageStore,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    refused: bool,
) -> None:
    """A check reads the CA, its ACL and its path once, passing or refused. Red under the memo
    key read separately from the judged read, as before #3188: two reads, two ``icacls`` runs."""
    ca = _ca(tmp_path)
    pin = "00" * 32 if refused else _sha(ca)
    reads = _count_reads(monkeypatch)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    if refused:
        with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
            await check("outbound", _OUT, _settings(ca, pin))
    else:
        await check("outbound", _OUT, _settings(ca, pin))
    assert reads[0] == 1


async def test_a_file_swapped_after_the_read_is_judged_as_read(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verdict judged is the one the remembered state came from. The file is swapped from a
    substitute to the pinned CA right after the check reads it: the check refuses the substitute
    it read, and the next check reads the pinned CA and passes. Red under a second read for the
    judgment, which judges the pinned CA and passes the check that read the substitute."""
    ca = _ca(tmp_path)
    good = ca.read_bytes()
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    _count_reads(monkeypatch, after=lambda: ca.write_bytes(good))
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
        await check("outbound", _OUT, _settings(ca, pin))
    await check("outbound", _OUT, _settings(ca, pin))


# --- item 2: a repeat of the last pass is remembered -------------------------------------------


def _path_verdict(ok: bool | None) -> Any:
    """A path check that finds one directory insecure (``ok`` False) or unjudged (``ok`` None)."""
    finding = ChainFinding("/anchors", "directory", ok is False, "writable by another account")
    return lambda _p: PathVerdict(ok, (finding,))


@pytest.mark.parametrize(
    ("acl", "path_ok", "event"),
    [
        (False, True, "acl_insecure"),
        (None, True, "acl_indeterminate"),
        (True, False, "path_insecure"),
        (True, None, "path_indeterminate"),
    ],
)
async def test_a_repeated_warn_mode_pass_writes_its_row_at_every_check(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acl: bool | None,
    path_ok: bool | None,
    event: str,
) -> None:
    """Under ``warn`` a CA whose ACL or path is exposed or unjudged passes and writes its
    violation row. A repeat of that pass writes the row again, at every check, as each check did
    before #3188: the pass memo never holds a pass that wrote a violation row. Red under the pass
    memo remembering every pass: one row for the three checks."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: acl)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok if path_ok else _path_verdict(path_ok))
    ca = _ca(tmp_path)
    judgments = _count_judgments(monkeypatch)
    check = ta.make_lane_anchor_check(store, enforcing=False)
    for _ in range(3):
        await check("outbound", _OUT, _settings(ca))
    events = [r["event"] for r in await _rows(store, _LABEL)]
    assert events.count(event) == 3 and events.count("observed") == 1, events
    assert judgments[0] == 3
    ca.write_bytes(_block(b"swapped"))
    await check("outbound", _OUT, _settings(ca))
    events = [r["event"] for r in await _rows(store, _LABEL)]
    assert events.count(event) == 4 and "changed" in events, events


async def test_a_repeated_clean_warn_mode_pass_is_remembered(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``warn`` a pass with an owner-only ACL and path writes no violation row, so the memo
    still holds it: a repeat is not judged again. Red under the memo dropped for every warn-mode
    pass, not only one that wrote a violation row."""
    ca = _ca(tmp_path)
    judgments = _count_judgments(monkeypatch)
    check = ta.make_lane_anchor_check(store, enforcing=False)
    for _ in range(3):
        await check("outbound", _OUT, _settings(ca))
    assert judgments[0] == 1
    assert [r["event"] for r in await _rows(store, _LABEL)] == ["observed"]


async def test_a_remembered_pass_does_not_pass_a_changed_file_acl_or_pin(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pass is returned from memory only for the same spec and verdict. A swapped file, an ACL
    that now reads as exposed, and a changed pin are each judged again, and the swapped file is
    refused. Red under the memo keyed on less than the spec and the whole verdict, such as the
    path alone."""
    ca = _ca(tmp_path)
    pin = _sha(ca)
    judgments = _count_judgments(monkeypatch)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    await check("outbound", _OUT, _settings(ca, pin))
    await check("outbound", _OUT, _settings(ca, pin))
    assert judgments[0] == 1  # the repeat came from memory
    good = ca.read_bytes()
    ca.write_bytes(_block(b"substitute"))
    with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
        await check("outbound", _OUT, _settings(ca, pin))
    assert judgments[0] == 2
    ca.write_bytes(good)
    await check("outbound", _OUT, _settings(ca, pin))
    assert judgments[0] == 3
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        await check("outbound", _OUT, _settings(ca, pin))
    assert judgments[0] == 4
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    await check("outbound", _OUT, _settings(ca))  # the pin dropped: a changed spec
    assert judgments[0] == 5


async def test_a_remembered_pass_whose_baseline_moved_is_judged_again(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeat skips the rows only while the audited baseline names the bytes it read. Another
    writer of the label, here a row for other bytes, moves it, and the next check is judged and
    writes ``changed`` back to these bytes. Red under the repeat trusting its memory over the
    store's baseline."""
    ca = _ca(tmp_path)
    judgments = _count_judgments(monkeypatch)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    await check("outbound", _OUT, _settings(ca))
    spec = ta.lane_anchor_spec("outbound", _OUT, _settings(ca))
    assert spec is not None
    await ta._record(store, spec, "changed", fingerprint="ab" * 32, previous=_sha(ca))
    await check("outbound", _OUT, _settings(ca))
    assert judgments[0] == 2
    rows = await _rows(store, _LABEL)
    assert rows[0]["event"] == "changed" and rows[0]["fingerprint"] == _sha(ca), rows
    await check("outbound", _OUT, _settings(ca))
    assert judgments[0] == 2  # the baseline names these bytes again


async def test_a_repeated_warn_mode_pass_still_warns(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A repeat under ``warn`` logs the warning a judged pass logs, so an operator who reloads
    sees the finding stand. Red under the repeat returning with no warning."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = _ca(tmp_path)
    check = ta.make_lane_anchor_check(store, enforcing=False)
    with caplog.at_level(logging.WARNING, logger=ta.log.name):
        for _ in range(2):
            await check("outbound", _OUT, _settings(ca))
    warned = [r for r in caplog.records if "writable by a non-owner" in r.getMessage()]
    assert len(warned) == 2, [r.getMessage() for r in caplog.records]


async def test_a_pass_the_store_stopped_is_not_remembered(
    tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``warn``, a pass whose ``observed`` row landed but whose ``acl_insecure`` row failed
    raises the store fault and is not remembered, so the next check writes the lost row. Red
    under the pass remembered before its rows were all written while a pass that wrote a
    violation row is remembered too: the baseline then names the bytes, and the repeat skips the
    row for good. The violation-row guard alone keeps this verdict out of the memory."""
    import json

    store = await MessageStore.open(tmp_path / "faulty.db")
    try:
        monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
        real = store.record_audit
        failed = [False]

        async def record_audit(action: str, *, actor: str | None, detail: str) -> None:
            if json.loads(detail).get("event") == "acl_insecure" and not failed[0]:
                failed[0] = True
                raise OSError(5, "Input/output error")
            await real(action, actor=actor, detail=detail)

        monkeypatch.setattr(store, "record_audit", record_audit)
        ca = _ca(tmp_path)
        check = ta.make_lane_anchor_check(store, enforcing=False)
        with pytest.raises(ta.AnchorStoreUnavailable):
            await check("outbound", _OUT, _settings(ca))
        await check("outbound", _OUT, _settings(ca))
        events = [r["event"] for r in await _rows(store, _LABEL)]
        assert events.count("acl_insecure") == 1 and events.count("observed") == 1, events
    finally:
        await store.close()


# --- item 3: a reload that removes a lane forgets it -------------------------------------------


async def test_a_reload_that_removes_a_lane_drops_its_mark_and_memory(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A lane its CA refused at start is marked, and the check remembers the refusal. A reload
    that removes the lane drops both, and a lane the reload keeps stays remembered. Red under the
    reload not pruning ``_anchor_refused``, or not telling the check."""
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    reg = _outbound_registry(ca, pin)
    kept = _ca(tmp_path, name="kept.pem")
    spec = Rest(url="https://kept.example.org/api", tls_ca_file=str(kept), tls_ca_pin=_sha(kept))
    reg.add_outbound(build_outbound_connection("KEPT", spec))
    runner = _runner(store, reg)
    check = runner._lane_anchor_check
    assert isinstance(check, RetainsLanes)
    await runner.start()
    try:
        assert ("outbound", _OUT) in runner._anchor_refused
        assert {("outbound", _OUT), ("outbound", "KEPT")} <= set(check._last)  # type: ignore[attr-defined]
        renamed = Registry()
        renamed.add_outbound(build_outbound_connection("KEPT", spec))
        await runner.reload(renamed)
        assert ("outbound", _OUT) not in runner._anchor_refused
        assert set(check._last) == {("outbound", "KEPT")}  # type: ignore[attr-defined]
    finally:
        await runner.stop()


async def test_a_reload_that_renames_a_lane_keeps_only_the_new_name(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A rename is a removal and an addition. With the file fixed, the reload checks the new
    name and drops the old name's mark and memory. Red under the prune reading the old graph."""
    ca = _ca(tmp_path)
    good = ca.read_bytes()
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    runner = _runner(store, _outbound_registry(ca, pin))
    check = runner._lane_anchor_check
    await runner.start()
    try:
        assert ("outbound", _OUT) in runner._anchor_refused
        ca.write_bytes(good)
        renamed = Registry()
        spec = Rest(url="https://partner.example.org/api", tls_ca_file=str(ca), tls_ca_pin=pin)
        renamed.add_outbound(build_outbound_connection("OUT2", spec))
        await runner.reload(renamed)
        assert not runner._anchor_refused
        assert set(check._last) == {("outbound", "OUT2")}
    finally:
        await runner.stop()


async def test_a_reload_of_a_stopped_runner_drops_removed_lanes(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A reload of a runner that is not running swaps the graph and returns early. It prunes
    there too. Red under the early return skipping the prune."""
    ca = _ca(tmp_path)
    runner = _runner(store, _outbound_registry(ca, _sha(ca)))
    check = runner._lane_anchor_check
    assert check is not None
    await check("outbound", _OUT, _settings(ca))
    runner._anchor_refused[("outbound", "GONE")] = (str(ca), None)
    await runner.reload(Registry())
    assert not runner._anchor_refused
    assert not check._last
