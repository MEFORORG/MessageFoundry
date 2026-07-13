# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Anonymizer integrations (ADR 0030 §6): the tee ``anonymize-captures`` subcommand, the harness
capture-sink hook, and the harness file-backed replay corpus — end to end."""

from __future__ import annotations

import asyncio
import json

import pytest

from messagefoundry.anon import anonymize
from messagefoundry.transports.mllp import frame
from harness.load.corpus import corpus_from_file
from harness.load.ids import ControlIds
from harness.load.profile import LoadProfileError, TypeMix
from harness.reconcile.capture import CaptureSink
from tee.__main__ import main as tee_main
from tee.store import RelayStore

_SALT = "integ-salt-0123456789abcdef"
_RAW = (
    "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
    "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"
)


async def _send_and_ack(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(frame(payload))
    await writer.drain()
    ack = await asyncio.wait_for(reader.read(4096), timeout=3)
    writer.close()
    await writer.wait_closed()
    return ack


async def _send_no_ack(port: int, payload: bytes) -> None:
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(frame(payload))
    await writer.drain()
    writer.close()
    await writer.wait_closed()


# --- harness capture-sink hook --------------------------------------------------------------------


def test_capture_sink_anonymizes_on_capture(tmp_path) -> None:
    out = tmp_path / "cap.jsonl"

    async def run() -> CaptureSink:
        sink = CaptureSink(out, ports=(0,), anonymizer=lambda r: anonymize(r, salt=_SALT))
        await sink.start()
        try:
            assert await _send_and_ack(sink.bound_ports[0], _RAW.encode("latin-1"))
        finally:
            await sink.stop()
        return sink

    sink = asyncio.run(run())
    assert sink.captured == 1 and sink.anon_failed == 0
    record = json.loads(out.read_text().splitlines()[0])
    assert record["control_id"] == "C1"  # MSH-10 kept => still correlatable
    assert "DOE" not in record["raw"] and "999" not in record["raw"]  # PHI scrubbed on capture


def test_capture_sink_fails_closed_on_real_engine_refusal(tmp_path) -> None:
    # The ENGINE anonymizer raises AnonError on a no-MSH body; the sink must catch it and write
    # nothing (regression for the catch-list gap the review found — a parser exception escaping).
    out = tmp_path / "cap.jsonl"
    no_msh = "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"  # no MSH -> engine refuses

    async def run() -> CaptureSink:
        sink = CaptureSink(out, ports=(0,), anonymizer=lambda r: anonymize(r, salt=_SALT))
        await sink.start()
        try:
            await _send_no_ack(sink.bound_ports[0], no_msh.encode("latin-1"))
            await asyncio.sleep(0.2)  # let the receiver process the frame
        finally:
            await sink.stop()
        return sink

    sink = asyncio.run(run())
    assert sink.captured == 0  # the refusal was caught, fail closed
    assert out.read_text() == ""  # the un-anonymized PHI never hit disk


def test_capture_sink_fails_closed_on_anon_error(tmp_path) -> None:
    out = tmp_path / "cap.jsonl"

    def boom(_: str) -> str:
        raise ValueError("anonymizer failure")

    async def run() -> CaptureSink:
        sink = CaptureSink(out, ports=(0,), anonymizer=boom)
        await sink.start()
        try:
            await _send_and_ack(sink.bound_ports[0], _RAW.encode("latin-1"))
        finally:
            await sink.stop()
        return sink

    sink = asyncio.run(run())
    assert sink.anon_failed == 1 and sink.captured == 0
    assert out.read_text() == ""  # nothing written => the un-anonymized PHI never hit disk


# --- tee anonymize-captures subcommand ------------------------------------------------------------


def _seed_capture(db: str, raw: bytes, *, direction: str = "corepoint_copy") -> None:
    async def seed() -> None:
        store = await RelayStore.open(db)
        try:
            await store.record_capture(direction=direction, control_id="C1", raw=raw)
        finally:
            await store.close()

    asyncio.run(seed())


def test_tee_anonymize_captures_end_to_end(tmp_path, monkeypatch) -> None:
    db = str(tmp_path / "tee.db")
    _seed_capture(db, _RAW.encode("latin-1"))
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    out = tmp_path / "ds.jsonl"

    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out)]) == 0
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["control_id"] == "C1"
    assert "DOE" not in record["raw"] and "999" not in record["raw"]

    # round-trip the de-identified dataset through the harness file corpus
    corpus = corpus_from_file(out, ControlIds(prefix="T"))
    outgoing = corpus.next(corpus.sampler(TypeMix(weights={"ADT": 1.0})))
    assert outgoing.code == "ADT"
    assert "DOE" not in outgoing.payload
    assert outgoing.control_id.startswith("T")  # MSH-10 restamped for replay


def test_tee_anonymize_captures_refuses_no_msh_body(tmp_path, monkeypatch) -> None:
    # A no-MSH capture cannot be anonymized -> the whole dataset is refused (fail closed), nothing
    # written (regression for the tee fail-open PHI leak the review found).
    db = str(tmp_path / "tee.db")
    _seed_capture(db, b"PID|1||999^^^H^MR||DOE^JOHN||19800101|M")
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    out = tmp_path / "ds.jsonl"
    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out)]) == 1
    assert not out.exists()  # no partial/leaky dataset written


def test_tee_anonymize_captures_requires_salt(tmp_path, monkeypatch) -> None:
    db = str(tmp_path / "tee.db")
    _seed_capture(db, _RAW.encode("latin-1"))
    monkeypatch.delenv("MEFOR_ANON_SALT", raising=False)
    rc = tee_main(["anonymize-captures", "--db", db, "--out", str(tmp_path / "x.jsonl")])
    assert rc == 2  # fail closed: no env salt


def test_tee_anonymize_captures_errors_when_no_captures(tmp_path, monkeypatch) -> None:
    db = str(tmp_path / "tee.db")

    async def empty() -> None:
        store = await RelayStore.open(db)
        await store.close()

    asyncio.run(empty())
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    rc = tee_main(["anonymize-captures", "--db", db, "--out", str(tmp_path / "x.jsonl")])
    assert rc == 1  # no captured bodies


# --- harness file corpus --------------------------------------------------------------------------


def test_corpus_from_file_rejects_empty_and_malformed(tmp_path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(LoadProfileError):
        corpus_from_file(empty, ControlIds(prefix="T"))

    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"not_raw": 1}\n', encoding="utf-8")
    with pytest.raises(LoadProfileError):
        corpus_from_file(bad, ControlIds(prefix="T"))


# --- tee anonymize-captures: PHI-safety guards (ANON-9) --------------------------------------------

# A forbidden token (a routable IP) in a KEPT field (MSH-4, sending facility). MSH is never scrubbed
# by the rule pass, so the IP survives anonymization and trips the leak_check -> LeakError. The tee's
# vendored IP detector keeps a literal default even without the publish guard, so this runs on the OSS
# mirror too.
#
# The IP is ASSEMBLED at runtime (never a source literal): the anon leak-check and the CI publish guard
# share scripts/publish/scan_forbidden.py, so a literal routable IP in this file trips the repo
# forbidden-content scan even though it is synthetic (public DNS, not a customer host).
_LEAK_IP = ".".join(["8"] * 4)
_LEAKY_RAW = (
    f"MSH|^~\\&|SAPP|{_LEAK_IP}|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
    "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"
)


def test_tee_anonymize_captures_keeps_bodies_off_stdout_stderr(
    tmp_path, monkeypatch, capsys
) -> None:
    # P0 PHI-safety guard: a successful de-id run reports only counts to stderr; no raw/pre-anon
    # body (or any PHI token from it) is ever echoed to stdout/stderr.
    db = str(tmp_path / "tee.db")
    _seed_capture(db, _RAW.encode("latin-1"))
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    out = tmp_path / "ds.jsonl"

    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out)]) == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "wrote 1 de-identified message" in combined  # count-only status was emitted
    # the dataset went to --out, never the console -> no raw body / PHI on stdout or stderr
    assert "DOE" not in combined
    assert "JOHN" not in combined
    assert "999" not in combined
    assert _RAW not in combined


def test_tee_anonymize_captures_leak_token_fails_closed(tmp_path, monkeypatch, capsys) -> None:
    # A forbidden token (the assembled routable IP) in a KEPT field (MSH-4) survives anonymization, so
    # anonymize_checked raises LeakError -> the CLI fails closed (rc1), writes nothing, and never
    # echoes the offending token or any body to stdout/stderr (only a count-only status).
    db = str(tmp_path / "tee.db")
    _seed_capture(db, _LEAKY_RAW.encode("latin-1"))
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    out = tmp_path / "ds.jsonl"

    assert tee_main(["anonymize-captures", "--db", db, "--out", str(out)]) == 1
    assert not out.exists()  # fail closed: no partial/leaky dataset written
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "forbidden token" in combined  # count-only fail-closed status
    assert "fail closed" in combined
    # the leaking value and PHI never surface
    assert _LEAK_IP not in combined
    assert "DOE" not in combined
    assert "999" not in combined
