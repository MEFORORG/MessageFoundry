# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 2.4.1 / 15.2.2 — the intake bounds the message-rate pacer could not reach (BACKLOG #1114).

The pacer ported to the raw-TCP, X12 and HTTP intakes on 2026-09-03 and stopped there. Re-measured at
``c57903c2`` before this change, by execution and with a positive control in the same run: ``MLLP``,
``Tcp``, ``X12`` and ``Http`` accept ``max_messages_per_second``, while ``DICOM``, ``File``, ``Sftp``
and ``Ftp`` each raised ``TypeError`` on it — and every one of the four constructed fine WITHOUT the
key first, so the rejection was a fact about the key and not a bad signature. So four externally-facing
intakes had no rate control **in any configuration**.

**They needed two different controls, and conflating them would have been the dishonest shortcut.**

*The poll sources* (``File``, ``Sftp``, ``Ftp``) have no sender to back-pressure — a partner writes to
a directory and leaves. Their gap was an unbounded **per-tick** iteration: one scan took every
candidate the listing returned. The ceiling **ships ON**, because the excess is deferred to the next
tick rather than refused, so a guessed number costs latency and never a message.

*The DICOM SCP* does have a peer to make wait, so its bound **ships OFF** for the same ruled reason the
pacer does (2026-08-11): a guessed rate throttles a real modality. Its unit is an **association**, not
a message, because ``pynetdicom`` owns the read loop — by ``EVT_C_STORE`` the object is already read
and decoded, and pacing after decode is the thing this item's record rejects by name.

**The load-bearing tests here are not that a bound bites.** They are
:func:`test_the_deferred_remainder_is_taken_by_later_ticks_never_dropped`, its RemoteFile sibling, and
:func:`test_a_paced_scp_still_establishes_every_association`. A bound that dropped or refused would
pass a "the rate is bounded" assertion while breaking the count-and-log invariant, which forbids
accept-and-drop.
"""

from __future__ import annotations

import asyncio
import inspect
import posixpath
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import wiring
from messagefoundry.config.connections_file import _TRANSPORTS
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import remotefile
from messagefoundry.transports.file import DEFAULT_MAX_FILES_PER_POLL, FileSource
from messagefoundry.transports.remotefile import RemoteFileSource, _RemoteClient

_MSG = b"MSH|^~\\&|SEND|FAC|RECV|FAC|20240101120000||ADT^A01|{}|P|2.5\rEVN|A01|20240101120000\r"


def _drop(directory: Path, count: int, *, prefix: str = "m") -> None:
    """Write ``count`` synthetic, PHI-free HL7 files with zero-padded, sortable names."""
    for index in range(count):
        (directory / f"{prefix}{index:03d}.hl7").write_bytes(
            _MSG.replace(b"{}", str(index).encode())
        )


# --- the local File source ------------------------------------------------------------------------


def _file_source(directory: Path, **settings: object) -> FileSource:
    base: dict[str, object] = {"directory": str(directory), "pattern": "*.hl7"}
    base.update(settings)
    return FileSource(Source(name="IB_FILE", type=ConnectorType.FILE, settings=base))


async def _tick(src: FileSource) -> list[bytes]:
    """Run exactly ONE scan and return what the handler saw. Deterministic on purpose: the ceiling is
    a per-TICK bound, so a test that let the poll loop run would be measuring the loop instead."""
    seen: list[bytes] = []

    async def handler(raw: bytes) -> None:
        seen.append(raw)
        return None

    src._handler = handler
    # start() normally creates these; these tests drive _scan_once directly to keep a per-TICK bound
    # measured per tick. Without them after_read="move" fails and the file is retried, which reads as
    # a duplicate rather than as a missing fixture.
    src._prepare_subdirs()
    await src._scan_once()
    return seen


async def test_the_tick_ceiling_ships_on() -> None:
    """The OPPOSITE default to the message-rate pacer, and the contrast is the point.

    ``mllp.DEFAULT_MAX_MESSAGES_PER_SECOND`` is ``None`` because a guessed rate throttles a real feed.
    Here the excess is deferred rather than refused, so the same reasoning selects the other answer —
    and that difference has to be pinned, or a later reader "fixes" one to match the other.
    """
    from messagefoundry.transports.mllp import DEFAULT_MAX_MESSAGES_PER_SECOND

    assert DEFAULT_MAX_MESSAGES_PER_SECOND is None, "the ruled-off pacer default moved"
    src = _file_source(Path("."))
    assert src.max_files_per_poll == DEFAULT_MAX_FILES_PER_POLL
    assert src.max_files_per_poll is not None and src.max_files_per_poll > 0


async def test_one_tick_takes_at_most_the_ceiling(tmp_path: Path) -> None:
    _drop(tmp_path, 7)
    assert len(await _tick(_file_source(tmp_path, max_files_per_poll=3))) == 3


async def test_the_deferred_remainder_is_taken_by_later_ticks_never_dropped(tmp_path: Path) -> None:
    """THE LOAD-BEARING TEST. Deferral is not a drop.

    Seven files, a ceiling of three: after three ticks every message has arrived exactly once and the
    directory is empty. A ceiling that discarded the excess would satisfy "one tick took at most
    three" above while silently breaking the count-and-log invariant.
    """
    _drop(tmp_path, 7)
    src = _file_source(tmp_path, max_files_per_poll=3)
    seen: list[bytes] = []
    for _ in range(3):
        seen += await _tick(src)
    assert len(seen) == 7, f"{7 - len(seen)} message(s) were dropped, not deferred"
    assert len(set(seen)) == 7, "a deferred file was re-emitted; deferral must not duplicate either"
    assert sorted(p.name for p in tmp_path.glob("*.hl7")) == [], "files were left behind"


async def test_the_ceiling_takes_the_first_n_in_the_configured_sort_order(tmp_path: Path) -> None:
    """Sort THEN cut. Cutting first would take an arbitrary subset and silently reorder a feed that
    asked for oldest-first, which is a worse defect than the unbounded tick."""
    _drop(tmp_path, 5)
    seen = await _tick(_file_source(tmp_path, max_files_per_poll=2, sort="name"))
    assert [raw.split(b"|")[9] for raw in seen] == [b"0", b"1"]


@pytest.mark.parametrize("disable", [0, None])
async def test_a_falsy_ceiling_disables_it_explicitly(tmp_path: Path, disable: object) -> None:
    """The same "falsy value disables the cap" rule the byte caps in this module already use."""
    _drop(tmp_path, 7)
    src = _file_source(tmp_path, max_files_per_poll=disable)
    assert src.max_files_per_poll is None
    assert len(await _tick(src)) == 7


async def test_the_ceiling_can_actually_fail(tmp_path: Path) -> None:
    """Proves the guard above is a guard: with the ceiling lifted, one tick takes everything.

    Without this, a ceiling that silently stopped being applied would leave every assertion here
    green — the tick would simply take all seven and no test would notice a bound had gone.
    """
    _drop(tmp_path, 7)
    assert len(await _tick(_file_source(tmp_path, max_files_per_poll=99))) == 7


async def test_a_tick_in_progress_stops_when_the_source_stops(tmp_path: Path) -> None:
    """``_scan_once`` consults the stop event per file, as ``remotefile.py`` already did.

    Measured before this change: ``file.py`` held exactly one ``_stop.is_set()``, in the ``_run``
    loop header, so a tick over a large drop ran to completion before ``stop()`` could return.
    """
    _drop(tmp_path, 7)
    src = _file_source(tmp_path, max_files_per_poll=0)
    seen: list[bytes] = []

    async def handler(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == 2:
            src._stop.set()
        return None

    src._handler = handler
    src._prepare_subdirs()
    await src._scan_once()
    assert len(seen) == 2, "the scan ignored the stop signal and drained the whole directory"
    assert len(list(tmp_path.glob("*.hl7"))) == 5, "the unscanned remainder must be left in place"


# --- the RemoteFile source (SFTP / FTP) ------------------------------------------------------------


class _FakeRemote(_RemoteClient):
    """A minimal in-memory remote share. Local to this module rather than imported from the
    RemoteFile transport suite, so a change there cannot silently reshape this bound's evidence."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = dict(files)
        self.retrieved: list[str] = []

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        return [
            (posixpath.basename(p), len(d))
            for p, d in self.files.items()
            if posixpath.dirname(p) == remote_dir
        ]

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        self.retrieved.append(path)
        return self.files[path]

    def store(self, path: str, data: bytes) -> None:
        self.files[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.files[dst] = self.files.pop(src)

    def remove(self, path: str) -> None:
        self.files.pop(path, None)

    def ensure_dir(self, remote_dir: str) -> bool:
        return False


def _remote_source(
    monkeypatch: pytest.MonkeyPatch, client: _FakeRemote, **over: object
) -> RemoteFileSource:
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: client)
    base: dict[str, Any] = {"host": "sftp.example.com", "remote_dir": "/in"}
    base.update(over)
    return RemoteFileSource(
        Source(name="IB_SFTP", type=ConnectorType.REMOTEFILE, settings=wiring.Sftp(**base).settings)
    )


async def _remote_tick(src: RemoteFileSource) -> list[bytes]:
    seen: list[bytes] = []

    async def handler(raw: bytes) -> None:
        seen.append(raw)
        return None

    src._handler = handler
    await src._poll_once()
    return seen


def _remote_files(count: int) -> dict[str, bytes]:
    return {f"/in/m{i:03d}.hl7": _MSG.replace(b"{}", str(i).encode()) for i in range(count)}


async def test_remote_one_poll_takes_at_most_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeRemote(_remote_files(7))
    src = _remote_source(monkeypatch, client, max_files_per_poll=3)
    assert len(await _remote_tick(src)) == 3
    assert len(client.retrieved) == 3, "the ceiling must cut BEFORE the network round trip"


async def test_remote_deferred_files_are_taken_by_later_polls_never_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The RemoteFile half of the load-bearing property."""
    client = _FakeRemote(_remote_files(7))
    src = _remote_source(monkeypatch, client, max_files_per_poll=3)
    seen: list[bytes] = []
    for _ in range(3):
        seen += await _remote_tick(src)
    assert len(seen) == 7 and len(set(seen)) == 7
    assert [p for p in client.files if p.startswith("/in/m")] == []


async def test_remote_ceiling_counts_matching_files_not_listing_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory full of non-matching names must not starve the few that match.

    Counting listing entries would have been the easier place to cut, and it would have made a share
    holding 100 ``.tmp`` files and 2 ``.hl7`` files ingest nothing at a ceiling of 2.
    """
    files = {f"/in/junk{i:03d}.tmp": b"x" for i in range(20)}
    files.update(_remote_files(2))
    src = _remote_source(monkeypatch, _FakeRemote(files), max_files_per_poll=2)
    assert len(await _remote_tick(src)) == 2


async def test_remote_falsy_ceiling_disables_it(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _remote_source(monkeypatch, _FakeRemote(_remote_files(7)), max_files_per_poll=0)
    assert src._max_files_per_poll is None
    assert len(await _remote_tick(src)) == 7


# --- the DICOM SCP association bound ---------------------------------------------------------------

pydicom = pytest.importorskip(
    "pydicom", reason="the DICOM association bound needs the [dicom] extra"
)
pynetdicom = pytest.importorskip(
    "pynetdicom", reason="the DICOM association bound needs the [dicom] extra"
)

from messagefoundry.transports.dicom import (  # noqa: E402
    DEFAULT_MAX_ASSOCIATIONS_PER_SECOND,
    DicomScpSource,
)

_SCP_AE = "MEFOR_PACE"


def _scp(**settings: object) -> DicomScpSource:
    base: dict[str, object] = {"ae_title": _SCP_AE, "host": "127.0.0.1", "port": 0}
    base.update(settings)
    return DicomScpSource(Source(name="IB_DICOM", type=ConnectorType.DIMSE, settings=base))


def test_the_association_bound_ships_off() -> None:
    """Unlike the poll ceiling and LIKE the message pacer — this one makes a real peer wait."""
    assert DEFAULT_MAX_ASSOCIATIONS_PER_SECOND is None
    src = _scp()
    assert src.max_associations_per_second is None
    assert src._pacer is None, "no rate configured must mean no pacer object at all"


def test_association_burst_defaults_to_one_seconds_worth() -> None:
    """Setting only the rate must not leave the burst at zero, which would pace the first peer."""
    assert _scp(max_associations_per_second=25).association_burst == 25.0
    assert _scp(max_associations_per_second=25, association_burst=100).association_burst == 100.0


def test_the_pacing_handlers_are_registered_only_when_a_rate_is_set() -> None:
    """An unpaced SCP — the shipped default — must run the handler set it always did.

    Read from ``_start_server`` rather than asserted in prose: the handlers are appended under a
    guard, and this is what fails if that guard is removed and every default install starts paying
    for two callbacks on its association path.
    """
    source = inspect.getsource(DicomScpSource._start_server)
    assert "if self._pacer is not None:" in source
    guard = source.index("if self._pacer is not None:")
    for event in ("EVT_CONN_OPEN", "EVT_ACCEPTED"):
        assert source.index(event) > guard, f"{event} is registered outside the pacer guard"


def test_the_wait_is_before_the_association_request_is_read() -> None:
    """The property that makes this honest, pinned against the events it is wired to.

    ``EVT_CONN_OPEN`` fires before the A-ASSOCIATE-RQ is read, so an over-budget peer's request is
    never taken in. ``EVT_C_STORE`` is after decode, which this item's record rejects by name — a wait
    there would delay a message the count-and-log invariant has already obliged us to account for.
    """
    source = inspect.getsource(DicomScpSource._start_server)
    assert re.search(r"EVT_CONN_OPEN,\s*self\._pace_association", source)
    assert re.search(r"EVT_ACCEPTED,\s*self\._charge_association", source)
    assert not re.search(r"EVT_C_STORE,\s*self\._pace_association", source)


def test_only_an_accepted_association_charges_the_budget() -> None:
    """A connection that opens and never associates charges nothing.

    Charging earlier would let a peer that submits no object spend a real modality's budget, which
    turns the limiter into the denial of service it exists to prevent (the HTTP listener's rule).
    """
    src = _scp(max_associations_per_second=10, association_burst=10)
    assert src._pacer is not None
    for _ in range(50):
        src._pace_association(object())  # opening alone must never deepen the debt
    assert src._pacer.deficit(now=time.monotonic()) == 0.0
    for _ in range(15):
        src._charge_association(object())
    assert src._pacer.deficit(now=time.monotonic()) > 0.0


async def test_stop_releases_an_outstanding_pacing_wait() -> None:
    """Shutdown must not wait out a rate debt. A 0.1/s rate owes tens of seconds; ``stop()`` clears it.

    **This test goes through ``stop()`` itself, and that is a correction it earned.** The first draft
    set ``_stopping`` by hand and asserted the WAIT responded to it. A mutation that deleted
    ``self._stopping.set()`` from ``stop()`` then survived: the wait was still interruptible and
    nothing was left to interrupt it, so the assertion held while shutdown had silently become
    unbounded. Testing the seam a caller actually uses is the difference.
    """
    src = _scp(max_associations_per_second=0.1, association_burst=1)
    assert src._pacer is not None

    async def handler(raw: bytes) -> str | None:  # pragma: no cover - nothing is stored here
        return None

    await src.start(handler)
    try:
        src._charge_association(object())
        src._charge_association(object())
        assert src._pacer.deficit(now=time.monotonic()) > 5.0, "fixture drifted: no real debt owed"
        waiter = threading.Thread(target=src._pace_association, args=(object(),))
        waiter.start()
        time.sleep(0.2)  # let it get into the wait
        assert waiter.is_alive(), "fixture drifted: the pacing wait returned before stop() ran"
        start = time.monotonic()
        await src.stop()
        waiter.join(timeout=5.0)
        assert not waiter.is_alive(), "stop() did not release the pacing wait"
        assert time.monotonic() - start < 5.0, "shutdown waited out the rate debt"
    finally:
        src._stopping.set()
        await src.stop()


def test_the_pacer_lock_is_not_held_across_the_wait() -> None:
    """A thread sleeping off its own debt must not block the bucket for every other association.

    Held across the wait, the lock would serialise the acceptor and turn a rate knob into the denial
    of service it guards against — the failure the ``EVT_CONN_OPEN`` threading measurement rules out.
    """
    src = _scp(max_associations_per_second=0.5, association_burst=1)
    assert src._pacer is not None
    src._charge_association(object())
    src._charge_association(object())
    waiter = threading.Thread(target=src._pace_association, args=(object(),))
    waiter.start()
    try:
        time.sleep(0.2)  # let it get into the wait
        assert src._pacer_lock.acquire(timeout=1.0), "the pacing wait holds the bucket lock"
        src._pacer_lock.release()
    finally:
        src._stopping.set()
        waiter.join(timeout=5.0)
    assert not waiter.is_alive()


_ECHOES = 6


async def _echo_run(**settings: object) -> tuple[list[bool], float]:
    """Open ``_ECHOES`` C-ECHO associations against one SCP; return what established and the elapsed
    seconds. Serial on purpose: the bound is on the ACCEPTANCE rate, so the arrivals must queue."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    src = _scp(**settings)

    async def handler(raw: bytes) -> str | None:  # pragma: no cover - C-ECHO stores nothing
        return None

    await src.start(handler)
    port = src.sockport
    try:

        def run() -> list[bool]:
            scu = AE(ae_title="MODALITY1")
            scu.add_requested_context(Verification)
            out: list[bool] = []
            for _ in range(_ECHOES):
                assoc = scu.associate("127.0.0.1", port, ae_title=_SCP_AE)
                out.append(bool(assoc.is_established))
                if assoc.is_established:
                    assoc.release()
            return out

        start = time.monotonic()
        established = await asyncio.to_thread(run)
        return established, time.monotonic() - start
    finally:
        await src.stop()


async def test_a_paced_scp_still_establishes_every_association() -> None:
    """THE LOAD-BEARING DICOM TEST: pacing waits, it never refuses.

    **The timing arm is a PAIRED comparison, not an absolute threshold, and that is a correction this
    test earned.** The first draft asserted the paced run took at least 0.15 s; its own unpaced
    control then measured 0.25 s for six loopback associations on this machine, so the threshold was
    satisfied by the baseline and proved nothing. Both arms now run here and the assertion is on the
    DIFFERENCE, which no machine speed can fake.

    **The expected delay is NOT ``(N - burst) / rate``, and the first draft asserted that it was.**
    Measured: at 5/s with one token, six associations came in 0.45 s slower than the control, not
    1.0 s. Two effects the naive figure ignores, both real properties of the control rather than test
    noise. The bucket REFILLS throughout the run, so the wall time the associations take is itself
    paying down the debt; and the LAST association's token is charged after it is accepted, with
    nobody left to wait on it. So the paced run settles at about ``(N - 1 - burst) / rate`` of total
    wall time — here ``(6 - 1 - 1) / 3 ≈ 1.33 s`` against a control near 0.4 s. The margin below is
    comfortably under that difference, and is a LOWER bound only: an upper bound would pin scheduler
    timing and make this the flaky test somebody deletes. What must hold exactly is that all six
    associate in both arms — a bound on this plane may delay a modality, never turn one away.
    """
    unpaced, unpaced_elapsed = await _echo_run()
    paced, paced_elapsed = await _echo_run(max_associations_per_second=3, association_burst=1)

    assert unpaced == [True] * _ECHOES, "the control arm could not associate; the fixture is broken"
    assert paced == [True] * _ECHOES, "pacing REFUSED an association; it may only ever wait"
    assert paced_elapsed - unpaced_elapsed >= 0.5, (
        f"pacing applied no measurable delay: paced {paced_elapsed:.3f}s vs unpaced "
        f"{unpaced_elapsed:.3f}s, against an expected paced total near 1.33s"
    )


# --- REACHABILITY: a connector that reads a key no author can write is not a shipped control -------


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("File", {"directory": "."}),
        ("Sftp", {"host": "h", "remote_dir": "/d"}),
        ("Ftp", {"host": "h", "remote_dir": "/d"}),
    ],
)
def test_the_poll_factories_reach_the_tick_ceiling(name: str, base: dict[str, object]) -> None:
    """Measured before this change: each raised ``TypeError`` on this keyword."""
    spec = getattr(wiring, name)(**base, max_files_per_poll=42)
    assert spec.settings["max_files_per_poll"] == 42


@pytest.mark.parametrize("transport", ["file", "sftp", "ftp"])
def test_the_toml_surface_reaches_the_tick_ceiling_too(transport: str) -> None:
    """``connections.toml`` desugars through the SAME factory, so the data surface follows for free.

    Asserted rather than assumed: this is exactly the claim the security prose makes about the pacing
    keys, and it is FALSE there for ``X12`` — ``_TRANSPORTS`` carries no ``x12`` row at all.
    """
    base: dict[str, object] = (
        {"directory": "."} if transport == "file" else {"host": "h", "remote_dir": "/d"}
    )
    assert _TRANSPORTS[transport](**base, max_files_per_poll=7).settings["max_files_per_poll"] == 7


def test_the_dicom_factory_reaches_the_association_bound() -> None:
    spec = wiring.DICOM(
        ae_title="AE", port=104, max_associations_per_second=9.5, association_burst=30.0
    )
    assert spec.settings["max_associations_per_second"] == 9.5
    assert spec.settings["association_burst"] == 30.0


def test_dicom_has_no_toml_surface_at_all_which_is_a_separate_gap() -> None:
    """Recorded so the missing ``dicom`` row reads as a measurement rather than an oversight.

    ``DICOM`` is absent from ``_TRANSPORTS`` entirely — the same shape as the ``x12`` gap, and the
    connector's own fail-closed error message already says so in its own words. The association bound
    is not a special case of that; closing it means adding the transport, a different decision.
    """
    assert "dicom" not in _TRANSPORTS
    assert "file" in _TRANSPORTS, "positive control — the map is populated"


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("File", {"directory": "."}),
        ("Sftp", {"host": "h", "remote_dir": "/d"}),
        ("Ftp", {"host": "h", "remote_dir": "/d"}),
        ("DICOM", {"ae_title": "AE"}),
    ],
)
def test_the_factory_still_rejects_an_unknown_key(name: str, base: dict[str, object]) -> None:
    """Positive control on every reachability test above. If these factories swallowed arbitrary
    keywords, each of those assertions would pass without the parameter existing at all."""
    with pytest.raises(TypeError):
        getattr(wiring, name)(**base, mefor_no_such_intake_key_1114=1.0)


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("File", {"directory": "."}),
        ("Sftp", {"host": "h", "remote_dir": "/d"}),
        ("Ftp", {"host": "h", "remote_dir": "/d"}),
    ],
)
def test_the_factory_default_matches_the_transport_default(
    name: str, base: dict[str, object]
) -> None:
    """The factory repeats the number as a literal (this module's shipped convention for the byte
    caps too), so the two can drift. Pinned, because a drifted default is invisible until a site
    behaves differently depending on which surface configured it."""
    assert (
        getattr(wiring, name)(**base).settings["max_files_per_poll"] == DEFAULT_MAX_FILES_PER_POLL
    )


def test_the_dicom_factory_default_is_still_off() -> None:
    """Exposing the keys must not turn the bound on. A defaulted number here would ship a guessed
    rate to every SCP deployment — the failure the 2026-08-11 ruling judged worse than no bound."""
    spec = wiring.DICOM(ae_title="AE")
    assert spec.settings["max_associations_per_second"] is None
    assert spec.settings["association_burst"] is None


# --- doc drift: the security prose must agree with the signatures, in BOTH directions --------------


def _ingest_row() -> str:
    doc = (Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    return next(line for line in doc.splitlines() if line.startswith("| **Ingest plane**"))


def test_the_ingest_row_agrees_with_the_poll_and_dicom_signatures() -> None:
    """Reachability is READ FROM THE SIGNATURE and the row must agree with whatever it says.

    The same shape the existing MLLP / raw-TCP / X12 / HTTP guard uses, and for the same reason:
    pinning either state as the correct one would settle a product question by build. Remove these
    controls and this test demands the row say so; keep them and it demands the row stop calling the
    DICOM SCP and the File / RemoteFile poll sources uncovered.
    """
    row = _ingest_row()
    ceiling_reaches = all(
        "max_files_per_poll" in inspect.signature(getattr(wiring, f)).parameters
        for f in ("File", "Sftp", "Ftp")
    )
    dicom_reaches = "max_associations_per_second" in inspect.signature(wiring.DICOM).parameters

    if ceiling_reaches:
        assert "max_files_per_poll" in row, (
            "File(), Sftp() and Ftp() now take a per-tick ceiling, so the ingest row must name it"
        )
        assert "the File / RemoteFile / Database poll sources" not in row, (
            "the row still lists the File / RemoteFile poll sources as uncovered; only the DATABASE "
            "poll has no ceiling now"
        )
    else:
        assert "the File / RemoteFile / Database poll sources" in row, (
            "no poll factory takes a per-tick ceiling, so the row must say the poll sources are "
            "uncovered rather than let a reader generalise from the listen intakes"
        )

    if dicom_reaches:
        assert "max_associations_per_second" in row, (
            "DICOM() now takes an association-rate bound, so the ingest row must name it"
        )
        assert "Not covered even when set:** the DICOM C-STORE SCP" not in row, (
            "DICOM() now takes an association-rate bound; the row may no longer call the SCP "
            "uncovered"
        )
    else:
        assert "the DICOM C-STORE SCP" in row, (
            "DICOM() takes no rate bound, so the row must say the SCP has none"
        )


def test_the_ingest_row_still_states_the_shipped_defaults_in_both_directions() -> None:
    """The two bounds ship OPPOSITE ways, and a row that stated only one would mislead either way.

    The DICOM bound is off, so a default install still has no rate bound on ANY listen intake — the
    fact that decides the ASVS cell. The poll ceiling is on, so the row must not be read as claiming
    the poll sources are unbounded either.
    """
    row = _ingest_row()
    assert "NO message-RATE bound" in row, (
        "the row must keep stating that a default install has no ingest message-rate bound; the "
        "DICOM association bound ships OFF and does not change that"
    )
    assert "deferred" in row or "defer" in row, (
        "the row must say what the per-tick ceiling does to the excess — deferral, not refusal — or "
        "a reader takes a shipped-on intake bound to mean dropped traffic"
    )
