# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's DICOM C-STORE SCU against the A-ABORT an engine SCP sends past its object ceiling
(owner ruling B462-R3, vault BACKLOG #4908).

Two halves. The SCU's DEFAULT ``max_object_bytes`` is clamped to the most any engine SCP holds of one
object before it aborts, on a connection built by ``DICOM()`` and on one built from raw settings,
while the SCP's own default stays where it was. And a store of an object over that ceiling that ends
with no C-STORE response is re-sent a bounded number of times, then dead-lettered, whatever cap the
SCU was given, so a set cap cannot hold the lane at its head forever.

Every listener binds ``127.0.0.1`` on an ephemeral port. Every object is a synthetic SR from
``tests/_dicom_sample.py``; none holds real PHI. The default-cap tests need no ``[dicom]`` extra;
the abort tests SKIP without it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from messagefoundry import DICOM
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.transports import dicom as dicom_module
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.dicom import DicomScpSource, DicomScuDestination

_MIB = 1024 * 1024

#: The SCP's object ceiling and its A-ABORT threshold, from the code rather than the doc.
_SCP_CEILING = DEFAULT_MAX_MESSAGE_BYTES
_SCP_ABORT_PAST = 2 * _SCP_CEILING


def _scu_from(settings: dict[str, object]) -> DicomScuDestination:
    return DicomScuDestination(
        Destination(name="OB_SCU", type=ConnectorType.DIMSE, settings=settings)
    )


def _scp_from(settings: dict[str, object]) -> DicomScpSource:
    return DicomScpSource(Source(type=ConnectorType.DIMSE, settings=settings))


# --- Step 1: the SCU's default cap ----------------------------------------------------------------


def test_a_factory_built_scu_defaults_to_the_engine_scps_abort_threshold() -> None:
    spec = DICOM(ae_title="MEFOR_SCU", host="127.0.0.1", called_ae_title="PACS")
    scu = _scu_from(dict(spec.settings))
    assert scu._max_object_bytes == _SCP_ABORT_PAST == 32 * _MIB


def test_a_raw_settings_scu_defaults_to_the_engine_scps_abort_threshold() -> None:
    scu = _scu_from({"ae_title": "MEFOR_SCU", "host": "127.0.0.1"})
    assert scu._max_object_bytes == _SCP_ABORT_PAST


@pytest.mark.parametrize(
    ("given", "expected"),
    [(128 * _MIB, 128 * _MIB), (_SCP_ABORT_PAST + 1, _SCP_ABORT_PAST + 1), (None, None), (0, None)],
)
def test_a_cap_the_author_sets_is_kept_by_both_builds(
    given: int | None, expected: int | None
) -> None:
    # The clamp is the default's alone: a site that sets a cap, larger or off, gets that cap. The
    # bounded re-send below is what keeps such a cap from holding the lane forever.
    built = DICOM(ae_title="MEFOR_SCU", host="127.0.0.1", max_object_bytes=given)
    assert built.settings["max_object_bytes"] == given
    assert _scu_from(dict(built.settings))._max_object_bytes == expected
    raw: dict[str, object] = {
        "ae_title": "MEFOR_SCU",
        "host": "127.0.0.1",
        "max_object_bytes": given,
    }
    assert _scu_from(raw)._max_object_bytes == expected


def test_the_scps_default_is_unchanged(caplog: pytest.LogCaptureFixture) -> None:
    # CONTROL: the SCP's configured default is still the 128 MiB constant, it still resolves to the
    # 16 MiB ingress ceiling on both builds, and a factory-built SCP still logs no clamp warning,
    # which it would if the factory had started passing it a different default.
    assert dicom_module.DEFAULT_MAX_OBJECT_BYTES == 128 * _MIB
    spec = DICOM(ae_title="MEFOR_SCP")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.dicom"):
        built = _scp_from({**spec.settings, "port": 0})
        raw = _scp_from({"ae_title": "MEFOR_SCP", "port": 0})
    assert built._max_object_bytes == raw._max_object_bytes == _SCP_CEILING
    assert built._max_inflated_bytes == raw._max_inflated_bytes
    assert not [r for r in caplog.records if "max_object_bytes" in r.getMessage()]


# --- Step 2: a store that ends in the SCP's abort -------------------------------------------------

_CAP = 4096


def _needs_dicom() -> None:
    pytest.importorskip("pydicom", reason="DICOM SCU tests need the [dicom] extra")
    pytest.importorskip("pynetdicom", reason="DICOM SCU tests need the [dicom] extra")


def _past_twice_the_cap() -> bytes:
    """A synthetic SR whose data set an engine SCP capped at ``_CAP`` aborts."""
    _needs_dicom()
    from tests import test_dicom_scp_receipt_bounds as bounds

    past = bounds._sr_of_at_least(2 * _CAP + 1)
    assert bounds._data_set_bytes(past) > 2 * _CAP, "CONTROL: the SCP aborts this object"
    return past


def _carry(data: bytes) -> str:
    from messagefoundry.parsing import RawMessage

    return RawMessage.from_bytes(data, "dicom").encode()


def _uncapped_scu(port: int, called_ae_title: str) -> DicomScuDestination:
    """An SCU with its cap off: the bound must hold whatever cap the SCU was given."""
    return _scu_from(
        {
            "ae_title": "MEFOR_SCU",
            "host": "127.0.0.1",
            "port": port,
            "called_ae_title": called_ae_title,
            "connect_timeout": 5.0,
            "timeout_seconds": 10.0,
            "max_object_bytes": None,
        }
    )


async def _outcomes(scu: DicomScuDestination, data: bytes, count: int) -> list[str]:
    payload, outcomes = _carry(data), []
    for _ in range(count):
        try:
            await scu.send(payload)
            outcomes.append("stored")
        except NegativeAckError as exc:
            assert exc.permanent is True and exc.code == "unanswered-over-ceiling"
            outcomes.append("final")
        except DeliveryError:
            outcomes.append("re-send")
    return outcomes


@pytest.mark.parametrize(
    ("ceiling", "expect_final"),
    [
        # The SCP here aborts past 2 x 4096 bytes, so the ceiling the SCU bounds against is moved
        # to match: the relation the shipped numbers hold, at a size a test can send.
        pytest.param(2 * _CAP, True, id="over-the-ceiling-is-final"),
        # CONTROL: the same object, SCP and abort, with the ceiling above the object. An unanswered
        # store the SCU cannot tie to the ceiling stays transient, however often it ends.
        pytest.param(64 * _CAP, False, id="under-the-ceiling-keeps-re-sending"),
    ],
)
async def test_the_scps_abort_is_bounded_only_for_an_object_over_the_ceiling(
    monkeypatch: pytest.MonkeyPatch, ceiling: int, expect_final: bool
) -> None:
    past = _past_twice_the_cap()
    from tests.test_dicom_scp import _SCP_AE
    from tests.test_dicom_scp_admission import _running_scp, _until

    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", ceiling)
    assert (len(past) > ceiling) is expect_final
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    sends = limit if expect_final else limit + 2
    settings: dict[str, object] = {"timeout_seconds": 30.0, "max_object_bytes": _CAP}
    async with _running_scp(settings) as scp:
        outcomes = await _outcomes(_uncapped_scu(scp.sockport, _SCP_AE), past, sends)
        # Every send ended in the engine SCP's own abort past twice its cap.
        await _until(lambda: scp._ended_log.refusals == sends)
    if expect_final:
        assert outcomes == ["re-send"] * (limit - 1) + ["final"]
    else:
        assert outcomes == ["re-send"] * sends


@contextmanager
def _scp_that_aborts(answers: list[int | None]) -> Iterator[int]:
    """A plain pynetdicom SCP, not the engine's: its C-STORE handler pops ``answers`` and aborts the
    association for ``None``, so the store ends with no response, or answers that status."""
    from pydicom.uid import ExplicitVRLittleEndian
    from pynetdicom import AE, evt

    from tests._dicom_sample import BASIC_TEXT_SR

    def handle_store(event: Any) -> int:
        answer = answers.pop(0)
        if answer is None:
            event.assoc.abort()
            return 0x0000
        return answer

    ae = AE(ae_title="PACS_SCP")
    ae.add_supported_context(BASIC_TEXT_SR, ExplicitVRLittleEndian)
    server = ae.start_server(
        ("127.0.0.1", 0), block=False, evt_handlers=[(evt.EVT_C_STORE, handle_store)]
    )
    assert server is not None and server.socket is not None
    try:
        yield int(server.socket.getsockname()[1])
    finally:
        server.shutdown()


@pytest.mark.parametrize(
    ("answer", "outcome"),
    [
        pytest.param(0x0000, "stored", id="after-a-success"),
        # Out of Resources is a transient refusal, but an answer: the peer is not aborting this.
        pytest.param(0xA700, "re-send", id="after-an-out-of-resources-answer"),
    ],
)
async def test_an_answered_store_starts_the_count_again(
    monkeypatch: pytest.MonkeyPatch, answer: int, outcome: str
) -> None:
    # The count is of unanswered ends in a row. A peer that aborted twice and then answered the
    # object leaves nothing behind that would end a later send of it early.
    _needs_dicom()
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(data) - 1)
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    answers: list[int | None] = [None] * (limit - 1) + [answer] + [None] * limit
    with _scp_that_aborts(answers) as port:
        scu = _uncapped_scu(port, "PACS_SCP")
        outcomes = await _outcomes(scu, data, 2 * limit)
    expected = ["re-send"] * (limit - 1) + [outcome] + ["re-send"] * (limit - 1) + ["final"]
    assert outcomes == expected
    assert scu._unanswered == {}


class _ResetMidStore:
    """An established association whose C-STORE raises, as a transport error pynetdicom passes up
    rather than turning into an empty status would."""

    is_established = True

    def send_c_store(self, dataset: object) -> object:
        raise ConnectionResetError("reset mid-store")

    def release(self) -> None:
        pass


async def test_an_error_raised_mid_store_counts_toward_the_same_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _needs_dicom()
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(data) - 1)
    scu = _uncapped_scu(1, "PACS_SCP")
    monkeypatch.setattr(scu, "_associate", lambda ae: _ResetMidStore())
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    raised: list[DeliveryError] = []
    for _ in range(limit):
        with pytest.raises(DeliveryError) as caught:
            await scu.send(_carry(data))
        raised.append(caught.value)
    assert [isinstance(exc, NegativeAckError) for exc in raised] == [False] * (limit - 1) + [True]
    final = raised[-1]
    assert isinstance(final, NegativeAckError) and final.code == "unanswered-over-ceiling"
    # The final refusal names the transport error as its cause.
    assert isinstance(final.__cause__, ConnectionResetError)


def _key(n: int) -> int:
    """A stand-in for _unanswered_key's hash: the count only needs keys that differ."""
    return n


def _scu_off() -> DicomScuDestination:
    return _scu_from({"ae_title": "MEFOR_SCU", "host": "127.0.0.1", "max_object_bytes": None})


def test_each_object_keeps_its_own_count_and_one_at_the_ceiling_is_never_counted() -> None:
    scu = _scu_off()
    size = dicom_module._ENGINE_SCP_ABORT_PAST_BYTES + 1
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    for _ in range(limit - 1):
        assert scu._count_unanswered(_key(1), size) is None
        assert scu._count_unanswered(_key(2), size) is None
    for n in (1, 2):
        final = scu._count_unanswered(_key(n), size)
        assert final is not None and final.permanent is True
    # The key is None for an object at the ceiling: never counted, however often it ends.
    at = b"x" * dicom_module._ENGINE_SCP_ABORT_PAST_BYTES
    assert dicom_module._unanswered_key(at) is None
    for _ in range(limit + 1):
        assert scu._count_unanswered(None, len(at)) is None
    assert scu._unanswered == {}


def test_the_key_is_the_whole_object_so_two_objects_of_one_size_never_share_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B8r: the key was (SOP instance UID, size), so every object with no UID shared one count per
    # size, and a second such object could end the first's sends early.
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", 3)
    first, second = dicom_module._unanswered_key(b"abcd"), dicom_module._unanswered_key(b"abce")
    assert first is not None and second is not None and first != second
    assert dicom_module._unanswered_key(b"abcd") == first, "a re-send meets its own count"


def _two_without_uid() -> tuple[bytes, bytes]:
    """Two synthetic SRs with no SOP Instance UID, alike but for one letter of the patient name, so
    one size. From one data set, since the UIDs make_sr_part10 generates vary in length."""
    _needs_dicom()
    from io import BytesIO

    from pydicom import dcmread

    from tests._dicom_sample import make_sr_part10

    ds = dcmread(BytesIO(make_sr_part10()))
    del ds.SOPInstanceUID
    made = []
    for name in ("Doe^Jane^A", "Doe^Jane^B"):
        ds.PatientName = name
        out = BytesIO()
        ds.save_as(out)
        made.append(out.getvalue())
    return made[0], made[1]


async def test_two_objects_with_no_uid_keep_their_own_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = _two_without_uid()
    assert len(first) == len(second) and first != second, "CONTROL: one size, two objects"
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(first) - 1)
    scu = _uncapped_scu(1, "PACS_SCP")
    monkeypatch.setattr(scu, "_associate", lambda ae: _ResetMidStore())
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    outcomes: list[str] = []
    for data in [first, second] * (limit - 1) + [first]:
        try:
            await scu.send(_carry(data))
        except NegativeAckError:
            outcomes.append("final")
        except DeliveryError:
            outcomes.append("re-send")
    # Interleaved, each object still gets its own limit - 1 re-sends before its own final.
    assert outcomes == ["re-send"] * (2 * (limit - 1)) + ["final"]


def test_an_unordered_lane_rotating_past_the_old_bound_still_goes_final() -> None:
    # B8r: the map held 64 counts, and a lane rotating 65 failing objects evicted each before its
    # third end, so none ever went final. 1,000 is far past that and well inside the bound.
    scu = _scu_off()
    size = dicom_module._ENGINE_SCP_ABORT_PAST_BYTES + 1
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    rotating = 1000
    assert rotating < dicom_module._UNANSWERED_REMEMBERED
    for _ in range(limit - 1):
        for n in range(rotating):
            assert scu._count_unanswered(_key(n), size) is None
    finals = [scu._count_unanswered(_key(n), size) for n in range(rotating)]
    assert all(final is not None and final.permanent for final in finals)
    assert scu._unanswered == {}


def test_the_oldest_count_is_dropped_past_the_ones_remembered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The eviction order, at a small bound so the test reads it directly.
    monkeypatch.setattr(dicom_module, "_UNANSWERED_REMEMBERED", 8)
    scu = _scu_off()
    size = dicom_module._ENGINE_SCP_ABORT_PAST_BYTES + 1
    remembered = dicom_module._UNANSWERED_REMEMBERED
    for n in range(remembered + 1):
        assert scu._count_unanswered(_key(n), size) is None
    assert len(scu._unanswered) == remembered
    assert _key(0) not in scu._unanswered and _key(remembered) in scu._unanswered
    # A count taken again moves to the newest end, so the next one dropped is another object's.
    assert scu._count_unanswered(_key(1), size) is None
    assert scu._count_unanswered(_key(remembered + 1), size) is None
    assert _key(1) in scu._unanswered and _key(2) not in scu._unanswered


def test_the_bound_is_sized_past_what_one_lane_could_hold_pending() -> None:
    # The stated sizing: defeating the bound takes more objects over the ceiling pending at once
    # than 2 TiB of store holds.
    pending = dicom_module._UNANSWERED_REMEMBERED * dicom_module._ENGINE_SCP_ABORT_PAST_BYTES
    assert pending >= 2 * 1024**4


async def test_forget_payload_gives_a_replay_every_send_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B8r: a row the retry policy dead-lettered with two unanswered ends kept its count, so a
    # replay of it went final after one send. The delivery worker now calls forget_payload there.
    _needs_dicom()
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(data) - 1)
    scu = _uncapped_scu(1, "PACS_SCP")
    monkeypatch.setattr(scu, "_associate", lambda ae: _ResetMidStore())
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    payload = _carry(data)
    for _ in range(limit - 1):
        with pytest.raises(DeliveryError) as caught:
            await scu.send(payload)
        assert not isinstance(caught.value, NegativeAckError)
    other = _carry(make_sr_part10())
    await scu.forget_payload(other)  # CONTROL: another object's row leaves this count alone
    assert len(scu._unanswered) == 1
    await scu.forget_payload(payload)
    assert scu._unanswered == {}
    for _ in range(limit - 1):  # the replay
        with pytest.raises(DeliveryError) as caught:
            await scu.send(payload)
        assert not isinstance(caught.value, NegativeAckError)
    with pytest.raises(NegativeAckError):
        await scu.send(payload)


async def test_the_final_refusal_names_no_cause_it_cannot_know(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # B8r: the message said an engine SCP aborts, but the SCU's own DIMSE timeout on a slow link
    # to any peer ends a store with no response too.
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", 3)
    scu = _scu_off()
    final = None
    for _ in range(dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING):
        final = scu._count_unanswered(_key(7), 4)
    assert final is not None
    text = str(final)
    assert "no response (an abort, a timeout or an error raised mid-store)" in text
    assert "engine SCP" not in text


class _RejectsTheContext:
    """An association the peer answered but with no accepted presentation context: permanent."""

    is_established = False
    rejected_contexts = ["the one proposed"]
    accepted_contexts: list[str] = []

    def release(self) -> None:
        pass


async def test_a_permanent_refusal_drops_the_count_so_a_replay_gets_every_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round 1: only the retry cap dropped the count, so a row the runner dead-lettered on another
    # permanent refusal kept it, and a replay went final early.
    _needs_dicom()
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(data) - 1)
    scu = _uncapped_scu(1, "PACS_SCP")
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    payload = _carry(data)
    monkeypatch.setattr(scu, "_associate", lambda ae: _ResetMidStore())
    for _ in range(limit - 1):
        with pytest.raises(DeliveryError):
            await scu.send(payload)
    assert len(scu._unanswered) == 1
    monkeypatch.setattr(scu, "_associate", lambda ae: _RejectsTheContext())
    with pytest.raises(NegativeAckError) as refused:
        await scu.send(payload)
    assert refused.value.permanent and refused.value.code == "no-accepted-context"
    assert scu._unanswered == {}
    monkeypatch.setattr(scu, "_associate", lambda ae: _ResetMidStore())
    outcomes = []
    for _ in range(limit):
        try:
            await scu.send(payload)
        except NegativeAckError:
            outcomes.append("final")
        except DeliveryError:
            outcomes.append("re-send")
    assert outcomes == ["re-send"] * (limit - 1) + ["final"]


async def test_an_answered_store_with_nothing_counted_pays_no_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round 1: the key was hashed before every association of an object over the ceiling.
    _needs_dicom()
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    monkeypatch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", len(data) - 1)
    real, hashed = dicom_module._unanswered_key, []

    def counting(object_bytes: bytes) -> int | None:
        hashed.append(len(object_bytes))
        return real(object_bytes)

    monkeypatch.setattr(dicom_module, "_unanswered_key", counting)
    with _scp_that_aborts([0x0000, None]) as port:
        scu = _uncapped_scu(port, "PACS_SCP")
        assert await _outcomes(scu, data, 1) == ["stored"]
        assert hashed == []
        # CONTROL: an unanswered end of the same object does hash it.
        assert await _outcomes(scu, data, 1) == ["re-send"]
    assert hashed == [len(data)]


def test_the_factorys_role_default_reads_as_what_it_means() -> None:
    import inspect

    default = inspect.signature(DICOM).parameters["max_object_bytes"].default
    assert repr(default) == "<each role's default>"


# --- The delivery worker's half: forget_payload once the retry cap dead-letters the row -----------


class _FailsAndRemembers:
    """A connector whose every send fails transiently, recording each forget_payload call."""

    def __init__(self) -> None:
        self.calls = 0
        self.forgotten: list[str] = []

    async def send(self, payload: str) -> None:
        self.calls += 1
        raise DeliveryError("connection reset")

    async def forget_payload(self, payload: str) -> None:
        self.forgotten.append(payload)

    async def aclose(self) -> None:
        return None


@pytest.mark.parametrize("max_attempts", [3, None], ids=["finite-cap", "no-cap"])
async def test_the_worker_forgets_a_payload_only_when_the_retry_cap_dead_letters_it(
    tmp_path: Any, max_attempts: int | None
) -> None:
    from messagefoundry.config.models import RetryPolicy
    from messagefoundry.store import MessageStore
    from tests.test_retry_exhausted_log import FAST, OUT, _enqueue, _stepped_runner

    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        dest = _FailsAndRemembers()
        runner = _stepped_runner(store, dest, RetryPolicy(max_attempts=max_attempts, **FAST))
        await _enqueue(store, 1)
        payloads: set[str] = set()
        for attempt in (1, 2, 3):
            item = await store.claim_next_fifo(OUT, now=1e12)
            assert item is not None
            payloads.add(item.payload)
            await runner._process_delivery_item(OUT, item)
            dead = await store.count_dead(allowed_channels=None)
            # The hook moves with the DEAD write, and never before it.
            assert len(dest.forgotten) == dead
            if attempt < 3 or max_attempts is None:
                assert dead == 0
        assert dest.calls == 3
        if max_attempts is not None:
            assert dead == 1 and len(payloads) == 1 and dest.forgotten == list(payloads)
    finally:
        await store.close()


class _ForgetBreaks(_FailsAndRemembers):
    async def forget_payload(self, payload: str) -> None:
        raise RuntimeError("cannot schedule new futures after shutdown")


async def test_a_failing_forget_hook_is_logged_and_the_arm_still_finishes(
    tmp_path: Any, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Round 1: the hook ran unguarded inside the except arm, so an error from it skipped the alert
    # checks that follow the dead-letter.
    from messagefoundry.config.models import RetryPolicy
    from messagefoundry.store import MessageStore
    from tests.test_retry_exhausted_log import FAST, OUT, _enqueue, _stepped_runner

    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        runner = _stepped_runner(store, _ForgetBreaks(), RetryPolicy(max_attempts=1, **FAST))
        checked: list[str] = []

        async def alert_checks(name: str) -> None:
            checked.append(name)

        monkeypatch.setattr(runner, "_delivery_failure_alert_checks", alert_checks)
        await _enqueue(store, 1)
        item = await store.claim_next_fifo(OUT, now=1e12)
        assert item is not None
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner"):
            await runner._process_delivery_item(OUT, item)
        assert await store.count_dead(allowed_channels=None) == 1
        assert checked == [OUT]
        assert any(
            "forget_payload failed" in r.getMessage() and "RuntimeError" in r.getMessage()
            for r in caplog.records
        )
    finally:
        await store.close()
