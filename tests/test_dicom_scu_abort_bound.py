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


def test_each_object_keeps_its_own_count_and_one_at_the_ceiling_is_never_counted() -> None:
    scu = _scu_from({"ae_title": "MEFOR_SCU", "host": "127.0.0.1", "max_object_bytes": None})
    size = dicom_module._ENGINE_SCP_ABORT_PAST_BYTES + 1
    limit = dicom_module._MAX_UNANSWERED_SENDS_OVER_CEILING
    for _ in range(limit - 1):
        assert scu._count_unanswered("1.2.3", size) is None
        assert scu._count_unanswered("1.2.4", size) is None
    for uid in ("1.2.3", "1.2.4"):
        final = scu._count_unanswered(uid, size)
        assert final is not None and final.permanent is True
    for _ in range(limit + 1):
        assert scu._count_unanswered("1.2.5", size - 1) is None
    assert scu._unanswered == {}


def test_the_oldest_count_is_dropped_past_the_ones_remembered() -> None:
    scu = _scu_from({"ae_title": "MEFOR_SCU", "host": "127.0.0.1", "max_object_bytes": None})
    size = dicom_module._ENGINE_SCP_ABORT_PAST_BYTES + 1
    remembered = dicom_module._UNANSWERED_REMEMBERED
    for n in range(remembered + 1):
        assert scu._count_unanswered(f"1.2.{n}", size) is None
    assert len(scu._unanswered) == remembered
    assert ("1.2.0", size) not in scu._unanswered
    assert (f"1.2.{remembered}", size) in scu._unanswered
    # A count taken again moves to the newest end, so the next one dropped is another object's.
    assert scu._count_unanswered("1.2.1", size) is None
    assert scu._count_unanswered(f"1.2.{remembered + 1}", size) is None
    assert ("1.2.1", size) in scu._unanswered and ("1.2.2", size) not in scu._unanswered
