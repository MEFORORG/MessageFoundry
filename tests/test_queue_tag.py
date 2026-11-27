# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The queue payload's routing tag (BACKLOG #2593).

The unit half pins :func:`queue_payload_aad`: every routing field is in the tag, a NULL is not the
text ``None``, and the tag keeps the ``queue.payload`` cell name. The integration half runs the
cross-backend contract in ``tests/_queue_tag_contract.py`` on SQLite; the Postgres and SQL Server
legs run the same contract from ``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

import ast
import json
import logging
import pathlib
import sqlite3
from typing import Any

import pytest

import messagefoundry
from messagefoundry.pipeline.alerts import QUEUE_TAG_SUBJECT, alert_cell_tag_failure
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    AADComponentError,
    AesGcmCipher,
    CipherError,
    aad_cell_name,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_COLUMNS,
    QueueTagError,
    open_queue_cell,
    queue_payload_aad,
    queue_row_aad,
)
from tests._queue_tag_contract import assert_queue_tag_contract

_BASE: dict[str, Any] = {
    "row_id": "row-1",
    "message_id": "msg-1",
    "stage": "outbound",
    "channel_id": "IB_A",
    "destination_name": "OB_A",
    "handler_name": None,
    "body_ref": None,
}


def _row(**changes: Any) -> dict[str, Any]:
    fields = {**_BASE, **changes}
    return {
        "id": fields["row_id"],
        "message_id": fields["message_id"],
        "stage": fields["stage"],
        "channel_id": fields["channel_id"],
        "destination_name": fields["destination_name"],
        "handler_name": fields["handler_name"],
        "body_ref": fields["body_ref"],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("row_id", "row-2"),
        ("message_id", "msg-2"),
        ("stage", "routed"),
        ("channel_id", "IB_B"),
        ("destination_name", "OB_B"),
        ("handler_name", "H1"),
        ("body_ref", "0" * 64),
    ],
)
def test_each_routing_field_changes_the_tag(field: str, value: object) -> None:
    assert queue_payload_aad(**{**_BASE, field: value}) != queue_payload_aad(**_BASE)


def test_a_null_destination_is_not_the_text_none_or_blank() -> None:
    """AC-10: ``cell_aad`` str()-encodes None, so NULL and ``"None"`` build the same bytes."""
    tags = {
        queue_payload_aad(**{**_BASE, "destination_name": value}) for value in (None, "None", "")
    }
    assert len(tags) == 3
    # The control that shows why the encoder matters: the id-only cell_aad conflates them. A cipher
    # refuses to bind that AAD (BACKLOG #5962), but its bytes are the same.
    assert cell_aad("queue", "payload", None) == cell_aad("queue", "payload", "None")
    with pytest.raises(AADComponentError):
        make_cipher(generate_key(), write_v2=True).encrypt(
            "x", aad=cell_aad("queue", "payload", None)
        )


def test_the_tag_still_names_its_cell_and_reads_off_a_row() -> None:
    aad = queue_payload_aad(**_BASE)
    assert aad_cell_name(aad) == ("queue", "payload")
    assert queue_row_aad(_row()) == aad
    assert aad != cell_aad("queue", "payload", "row-1")  # not the old id-only tag
    with pytest.raises((KeyError, IndexError)):  # a reader that skipped a column fails closed
        queue_row_aad({k: v for k, v in _row().items() if k != "handler_name"})


def test_open_queue_cell_binds_the_row_and_its_reference() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    row = _row()
    row["payload"] = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    assert open_queue_cell(cipher, row) == "SYNTH-BODY"  # control
    with pytest.raises(QueueTagError, match="integrity"):
        open_queue_cell(cipher, {**row, "destination_name": "OB_B"})
    with pytest.raises(QueueTagError, match="no sealed payload"):
        open_queue_cell(cipher, {**row, "payload": ""})
    assert issubclass(QueueTagError, CipherError)  # every claim's dead-letter path catches it

    ref_row = _row(body_ref="a" * 64)
    ref_row["payload"] = cipher.encrypt("a" * 64, aad=queue_row_aad(ref_row))
    assert open_queue_cell(cipher, ref_row) == "a" * 64  # control
    with pytest.raises(QueueTagError):  # re-pointed: the kind still matches, the reference does not
        open_queue_cell(cipher, {**ref_row, "body_ref": "b" * 64})
    with pytest.raises(QueueTagError):  # dropped: the cell was sealed as a reference
        open_queue_cell(cipher, {**ref_row, "body_ref": None})


def test_a_keyless_store_delivers_an_empty_inline_body() -> None:
    """Keyless, an empty body is stored as ''. Only a reference row must hold a value there."""
    cipher = make_cipher(None)
    assert open_queue_cell(cipher, {**_row(), "payload": ""}) == ""
    with pytest.raises(QueueTagError):
        open_queue_cell(cipher, {**_row(body_ref="a" * 64), "payload": ""})


def test_the_tag_failure_hook_and_alert() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[tuple[str, str]] = []
    cipher.set_tag_failure_hook(lambda table, reason: seen.append((table, reason)))
    cipher.report_tag_failure("queue", "a reason")
    assert seen == [("queue", "a reason")]

    def _raising(table: str, reason: str) -> None:
        raise RuntimeError("an alert sink that fails")

    cipher.set_tag_failure_hook(_raising)
    cipher.report_tag_failure("queue", "swallowed")  # a raising hook never escapes

    class _Sink:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
            self.calls.append((name, reason))

    sink = _Sink()
    alert_cell_tag_failure(sink, "queue", "r")  # type: ignore[arg-type]
    assert sink.calls == [(QUEUE_TAG_SUBJECT, "r")]


_STORE_DIR = pathlib.Path(messagefoundry.__file__).resolve().parent / "store"


def _queue_payload_literals(path: pathlib.Path) -> int:
    count = 0
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", None)) == "cell_aad"
            and len(node.args) >= 2
            and all(isinstance(a, ast.Constant) for a in node.args[:2])
            and [a.value for a in node.args[:2] if isinstance(a, ast.Constant)]
            == ["queue", "payload"]
        ):
            count += 1
    return count


def test_one_helper_builds_every_queue_payload_tag() -> None:
    """No store module builds the queue payload's associated data except through the helper."""
    counts = {
        p.name: _queue_payload_literals(p)
        for p in sorted(_STORE_DIR.rglob("*.py"))
        if _queue_payload_literals(p)
    }
    # The helper's own frame is the one call; every backend reaches it through queue_payload_aad.
    assert counts == {"queue_tag.py": 1}, counts
    for backend in ("store.py", "postgres.py", "sqlserver.py"):
        source = (_STORE_DIR / backend).read_text(encoding="utf-8")
        assert "queue_payload_aad(" in source and "queue_row_aad" in source, backend


def test_queue_tag_columns_are_queue_columns() -> None:
    conn = sqlite3.connect(":memory:")
    from messagefoundry.store.store import _SCHEMA

    conn.executescript(_SCHEMA)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(queue)")}
    conn.close()
    # body_ref is added by the migration on SQLite; the rest are in the base schema.
    assert set(QUEUE_TAG_COLUMNS) - {"body_ref"} <= columns


async def test_queue_tag_contract_sqlite(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "queue-tag.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    side.row_factory = sqlite3.Row
    try:

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            side.execute(sql, params)
            side.commit()

        async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            return [dict(r) for r in side.execute(sql, params).fetchall()]

        await assert_queue_tag_contract(store, raw, fetch, store_once=True)
    finally:
        side.close()
        await store.close()


async def test_rotation_reseals_the_tag_and_steps_over_a_cell_that_fails_it(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``rotate-key``'s queue pass re-seals each payload under its own tag. A cell that fails its tag
    under a key the process holds, dead or still pending, is left as it is and counted, so it cannot
    block every rotation. A cell under a key that is not supplied still stops it (control)."""
    db = tmp_path / "rotate.db"
    old_key, new_key = generate_key(), generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(old_key, write_v2=True))
    side = sqlite3.connect(db, timeout=30)
    try:
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[("OB_KEEP", "B1")])
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[("OB_BENT", "B2")])
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[("OB_LIVE", "B3")])
        side.execute("UPDATE queue SET destination_name='OB_ELSE' WHERE destination_name='OB_BENT'")
        side.execute("UPDATE queue SET destination_name='OB_X' WHERE destination_name='OB_LIVE'")
        side.commit()
        assert await store.claim_next_fifo("OB_ELSE") is None  # refused and dead-lettered
    finally:
        await store.close()

    unsupplied = await MessageStore.open(db, cipher=make_cipher(new_key, write_v2=True))
    try:
        with pytest.raises(CipherError, match="no configured key"):  # the old key is missing
            await unsupplied.reencrypt_to_active()
    finally:
        await unsupplied.close()

    rotated = await MessageStore.open(
        db, cipher=make_cipher(new_key, retired_b64=[old_key], write_v2=True)
    )
    try:
        with caplog.at_level("WARNING"):
            assert await rotated.reencrypt_to_active() >= 1
        assert "rotation left 2 queue.payload value(s)" in caplog.text
        item = await rotated.claim_next_fifo("OB_KEEP")
        assert item is not None and item.payload == "B1"  # re-sealed under the new key and tag
        assert await rotated.claim_next_fifo("OB_X") is None  # still refused after the rotation
    finally:
        side.close()
        await rotated.close()


def test_a_key_or_format_problem_is_not_a_tag_failure() -> None:
    """Only a marked cell under a held key that fails its tag is a tag failure. An unmarked value
    and a cell under a key that is not configured raise the cipher's own error."""
    old_key = generate_key()
    sealer = make_cipher(old_key, write_v2=True)
    row = _row()
    sealed = sealer.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    other = make_cipher(generate_key(), write_v2=True)
    with pytest.raises(CipherError) as missing:
        open_queue_cell(other, {**row, "payload": sealed})
    assert not isinstance(missing.value, QueueTagError)
    with pytest.raises(CipherError) as unmarked:
        open_queue_cell(sealer, {**row, "payload": "SYNTH-PLAINTEXT"})
    assert not isinstance(unmarked.value, QueueTagError)
    with pytest.raises(QueueTagError):  # control: the held key, the wrong row
        open_queue_cell(sealer, {**row, "channel_id": "IB_B", "payload": sealed})


def _raising_transit() -> tuple[Any, Any]:
    """A real :class:`TransitCipher` over a fake hvac client whose decrypt raises what it is set."""
    from messagefoundry.store.crypto_transit import TransitCipher  # noqa: PLC0415

    class _Transit:
        error: Exception | None = None

        def decrypt_data(self, **_kw: Any) -> Any:
            assert self.error is not None
            raise self.error

    class _Client:
        def __init__(self, transit: _Transit) -> None:
            self.secrets = type("S", (), {"transit": transit})()

    transit = _Transit()
    return TransitCipher(_Client(transit), "mefor-store"), transit


def test_a_transit_outage_is_not_a_queue_tag_failure() -> None:
    """BACKLOG #5765: Vault Transit cannot name its keys, so ``is_tag_failure`` counts every marked
    value as held. A failure reaching or authenticating to Vault (an unreachable Vault, a timeout,
    a 5xx, a refused token's 403) must raise the cipher's own error, never :class:`QueueTagError`,
    so a claim does not dead-letter the row with a false ``integrity_drift`` alert. A 404 names a
    path built from engine config, such as a missing mount, so it gives no verdict either. A 400 is a
    verdict and still a tag failure. Control: Vault's AEAD refusal of a moved cell is still
    one."""
    pytest.importorskip("hvac")
    import requests  # noqa: PLC0415
    from hvac.exceptions import (  # type: ignore[import-untyped]  # noqa: PLC0415
        Forbidden,
        InternalServerError,
        InvalidPath,
        InvalidRequest,
    )

    from messagefoundry.store.crypto import CipherUnavailableError  # noqa: PLC0415
    from messagefoundry.store.queue_tag import is_transient_open_failure  # noqa: PLC0415

    cipher, transit = _raising_transit()
    row = {**_row(), "payload": "mfenc:v3:vault:v1:AAAA"}
    outages: list[Exception] = [
        requests.exceptions.ConnectionError("connection refused"),
        requests.exceptions.ReadTimeout("read timed out"),
        InternalServerError("upstream"),
        Forbidden(errors=["permission denied"]),
        # A 404 names a path built from engine config, such as a missing mount: no verdict.
        InvalidPath(errors=["no handler for route"]),
    ]
    for exc in outages:
        transit.error = exc
        with pytest.raises(CipherError) as refused:
            open_queue_cell(cipher, row)
        assert not isinstance(refused.value, QueueTagError), exc
        assert is_transient_open_failure(refused.value), exc
    assert is_transient_open_failure(CipherUnavailableError("down"))
    assert not is_transient_open_failure(QueueTagError("integrity"))
    assert not is_transient_open_failure(OSError("not a cipher error"))

    # A refusal Vault did give a verdict on still counts as a tag failure: this fix narrows the
    # control by the outage case only, and does not rest it on matching Vault's AEAD error text.
    transit.error = InvalidRequest(errors=["ciphertext version is disallowed by policy (too old)"])
    with pytest.raises(QueueTagError) as policy:
        open_queue_cell(cipher, row)
    assert not is_transient_open_failure(policy.value)

    # Control: Transit's AEAD refusal of a cell moved to another row is still a tag failure.
    transit.error = InvalidRequest(errors=["cipher: message authentication failed"])
    with pytest.raises(QueueTagError) as moved:
        open_queue_cell(cipher, row)
    assert not is_transient_open_failure(moved.value)


def test_the_reply_status_attribute_is_the_one_the_vault_client_records() -> None:
    """BACKLOG #5765: the queue classifier reads a 5xx that hvac raises as ``UnexpectedError`` by
    the status the store's Vault client records, under the name ``keyprovider_vault`` sets."""
    from messagefoundry.store import keyprovider_vault, queue_tag  # noqa: PLC0415

    assert queue_tag._REPLY_STATUS_ATTR == keyprovider_vault._REPLY_STATUS_ATTR


def _caused(cause: BaseException | None, cls: type[CipherError] = CipherError) -> CipherError:
    error = cls("Transit decrypt failed")
    error.__cause__ = cause
    return error


def with_reply_status[E: BaseException](exc: E, status: int) -> E:
    """``exc`` carrying ``status`` as the store's Vault client records it (BACKLOG #8222), under
    the client's own attribute name, so a rename cannot leave these tests setting a dead one."""
    from messagefoundry.store import keyprovider_vault  # noqa: PLC0415

    setattr(exc, keyprovider_vault._REPLY_STATUS_ATTR, status)
    return exc


def test_the_no_verdict_rule_reads_the_status_first_on_any_cause() -> None:
    """BACKLOG #5765: only a 400, a 413 or a tag check that ran and failed is a verdict on
    the row. A recorded reply status decides first, whatever class carries it. A cause the rule
    names nowhere keeps the verdict it had before the rule was revised."""
    pytest.importorskip("hvac")
    import requests  # noqa: PLC0415
    from hvac import exceptions as hv  # type: ignore[import-untyped]  # noqa: PLC0415

    from messagefoundry.store.crypto import UnauthenticatedCipherError  # noqa: PLC0415
    from messagefoundry.store.queue_tag import is_transient_open_failure  # noqa: PLC0415
    from messagefoundry.transports.bounded_read import (  # noqa: PLC0415
        EgressReplyError,
        ResponseTooLargeError,
    )
    from messagefoundry.transports.strict_requests import VaultHopRefused  # noqa: PLC0415

    no_verdict: list[BaseException] = [
        hv.Unauthorized(),
        hv.Forbidden(),
        hv.RateLimitExceeded(),
        hv.VaultDown(),
        hv.UnexpectedError("no status recorded"),
        with_reply_status(hv.UnexpectedError("timeout"), 408),
        with_reply_status(TypeError("unreadable body"), 503),
        with_reply_status(AttributeError("unreadable body"), 401),
        with_reply_status(hv.InvalidRequest(), 503),  # the status wins over the class
        hv.InvalidPath(),
        with_reply_status(hv.InvalidPath(), 404),
        requests.exceptions.SSLError("certificate verify failed"),
        requests.exceptions.ChunkedEncodingError("connection broken"),
        ConnectionResetError("reset by peer"),
        # The strict Vault adapter raises these unwrapped: a hop it refused, a reply it would not
        # read, and a reply past its byte bound.
        VaultHopRefused("vault_transit: refused"),
        EgressReplyError("a reply the engine cannot read strictly"),
        ResponseTooLargeError("too large"),
    ]
    for cause in no_verdict:
        assert is_transient_open_failure(_caused(cause)), cause
    verdict: list[BaseException | None] = [
        hv.InvalidRequest(),
        with_reply_status(hv.UnexpectedError("too large"), 413),
        with_reply_status(hv.Forbidden(), 400),  # the status wins over the class
        with_reply_status(TypeError("unreadable body"), 400),
        hv.ParamValidationError("client-side"),  # unknown here: as before the rule
        KeyError("data"),  # a malformed reply, unknown here: as before the rule
        None,
    ]
    for maybe in verdict:
        assert not is_transient_open_failure(_caused(maybe)), maybe
    # A tag check that ran and failed is a verdict whatever its cause says.
    assert not is_transient_open_failure(
        _caused(with_reply_status(hv.VaultDown(), 503), UnauthenticatedCipherError)
    )


async def test_the_response_worker_dead_letters_a_token_whose_tag_fails_after_its_claim(
    tmp_path: pathlib.Path,
) -> None:
    """BACKLOG #5982: the worker step itself, not only the store read. A token changed after its
    claim is dead-lettered under the tag-failure error, audited once, and re-ingresses nothing."""
    from messagefoundry.pipeline.wiring_runner import _ItemOutcome  # noqa: PLC0415
    from messagefoundry.store.queue_tag import QUEUE_TAG_FAILED_ACTION  # noqa: PLC0415
    from messagefoundry.store.store import (  # noqa: PLC0415
        REINGRESS_TOKEN_TAG_FAILED,
        MessageStatus,
        OutboxStatus,
        Stage,
    )
    from tests import _undecryptable_reply_contract as reply  # noqa: PLC0415
    from tests._erased_reply_contract import LOOP, children, status_of  # noqa: PLC0415

    store = await MessageStore.open(
        tmp_path / "worker.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    try:

        async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            cur = await store._db.execute(sql, params)
            return [dict(r) for r in await cur.fetchall()]

        mid = await reply.captured(store, control="QT-W", now=1.0)
        item = await store.claim_next_fifo(LOOP, stage=Stage.RESPONSE.value)
        assert item is not None
        await store._db.execute("UPDATE queue SET handler_name='H_QT_W' WHERE id=?", (item.id,))
        await store._db.commit()

        outcome = await reply.runner(store)._process_response_item(LOOP, item)

        assert outcome[0] is _ItemOutcome.PROCESSED
        assert (await reply.token_of(fetch, mid))["status"] == OutboxStatus.DEAD.value
        [row] = await fetch("SELECT last_error FROM queue WHERE id=?", (item.id,))
        last_error = store.cipher().decrypt(
            row["last_error"], aad=cell_aad("queue", "last_error", item.id)
        )
        assert last_error == REINGRESS_TOKEN_TAG_FAILED
        assert await status_of(store, mid) == MessageStatus.ERROR.value
        audited = await fetch(
            "SELECT detail FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,)
        )
        assert len(audited) == 1 and item.id[:12] in audited[0]["detail"], audited
        assert await children(fetch) == []
    finally:
        await store.close()


async def test_the_response_worker_labels_a_corrupt_token_corrupt_not_tag_drift(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5982 step 2: a token whose payload turns corrupt after its claim, under a key the
    store holds, is dead-lettered, audited and alerted as before, and named corrupt rather than a
    failed tag, in its ``last_error`` and in the worker's WARNING."""
    from messagefoundry.pipeline.wiring_runner import _ItemOutcome  # noqa: PLC0415
    from messagefoundry.store.queue_tag import (  # noqa: PLC0415
        QUEUE_CORRUPT_ALERT_TABLE,
        QUEUE_TAG_FAILED_ACTION,
    )
    from messagefoundry.store.store import (  # noqa: PLC0415
        REINGRESS_TOKEN_CORRUPT,
        REINGRESS_TOKEN_TAG_FAILED,
        MessageStatus,
        OutboxStatus,
        Stage,
    )
    from tests import _undecryptable_reply_contract as reply  # noqa: PLC0415
    from tests._erased_reply_contract import LOOP, children, status_of  # noqa: PLC0415

    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner")
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    alerts: list[tuple[str, str]] = []
    cipher.set_tag_failure_hook(lambda table, reason: alerts.append((table, reason)))
    store = await MessageStore.open(tmp_path / "worker.db", cipher=cipher)
    try:

        async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            cur = await store._db.execute(sql, params)
            return [dict(r) for r in await cur.fetchall()]

        mid = await reply.captured(store, control="QT-C", now=1.0)
        item = await store.claim_next_fifo(LOOP, stage=Stage.RESPONSE.value)
        assert item is not None
        [cell] = await fetch("SELECT payload FROM queue WHERE id=?", (item.id,))
        corrupt = str(cell["payload"]).rsplit(":", 1)[0] + ":AAAAA"  # bad base64, held key
        assert cipher.holds_key_for(corrupt)
        await store._db.execute("UPDATE queue SET payload=? WHERE id=?", (corrupt, item.id))
        await store._db.commit()

        outcome = await reply.runner(store)._process_response_item(LOOP, item)

        assert outcome[0] is _ItemOutcome.PROCESSED
        assert (await reply.token_of(fetch, mid))["status"] == OutboxStatus.DEAD.value
        [row] = await fetch("SELECT last_error FROM queue WHERE id=?", (item.id,))
        last_error = store.cipher().decrypt(
            row["last_error"], aad=cell_aad("queue", "last_error", item.id)
        )
        assert last_error == REINGRESS_TOKEN_CORRUPT, last_error
        assert last_error != REINGRESS_TOKEN_TAG_FAILED
        assert "corrupt" in last_error and "queue tag" not in last_error, last_error
        assert await status_of(store, mid) == MessageStatus.ERROR.value
        audited = await fetch(
            "SELECT detail FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,)
        )
        assert len(audited) == 1 and item.id[:12] in audited[0]["detail"], audited
        assert json.loads(audited[0]["detail"])["cause"] == "corrupt", audited
        assert len(alerts) == 1 and alerts[0][0] == QUEUE_CORRUPT_ALERT_TABLE, alerts
        worker = [
            r.getMessage()
            for r in caplog.records
            if r.name == "messagefoundry.pipeline.wiring_runner" and item.id in r.getMessage()
        ]
        assert len(worker) == 1, worker
        assert "corrupt" in worker[0] and "integrity tag" not in worker[0], worker
        assert await children(fetch) == []
    finally:
        await store.close()


def test_an_open_fault_names_a_non_cipher_error_by_its_type_alone() -> None:
    """BACKLOG #5735: the T17 path logs a :class:`QueueOpenFault` at ERROR, so a failed store
    write's driver text, which can echo a value, must not ride in it. A cipher error's own text,
    which never holds a value, is kept."""
    from messagefoundry.store.crypto import CipherUnavailableError  # noqa: PLC0415
    from messagefoundry.store.queue_tag import queue_open_fault  # noqa: PLC0415

    leaked = "String or binary data would be truncated. Truncated value: 'DOE^JANE'"
    assert str(queue_open_fault(OSError(leaked))) == "OSError"
    assert str(queue_open_fault(RuntimeError(leaked))) == "RuntimeError"
    assert str(queue_open_fault(CipherUnavailableError("down"))) == "CipherUnavailableError: down"
