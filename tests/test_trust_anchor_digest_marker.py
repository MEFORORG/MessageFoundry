# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3425: a trust-anchor pin and an audited anchor observation name their digest.

A pin may be ``sha256:<hex>``, and a bare pin still reads as SHA-256. Each ``auth.trust_anchor`` row
carries ``algorithm``, and a row with none, as every row written before this, reads as SHA-256.
The change check compares in the digest of the earlier row. A digest name the release does not
compile in is refused: a pin naming one refuses, and a stored row naming one is skipped."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.trust_anchors import (
    AUDIT_ACTION,
    AnchorSpec,
    TrustAnchorError,
    enforce_anchor,
    parse_anchor_pin,
    run_anchor_preflight,
)
from messagefoundry.config.wiring import _check_tls_ca_pin
from messagefoundry.store import MessageStore
from tests.test_trust_anchors import _block, _path_ok, _rows


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Row counts here are about fingerprints, so the host's temp ACL and path cannot add rows."""
    monkeypatch.setattr(ta, "_LOADED", {})
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _colons(fp: str) -> str:
    return ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))


def _anchor(tmp_path: Path, body: bytes = b"marker") -> tuple[Path, str]:
    p = tmp_path / "ca.pem"
    p.write_bytes(_block(body))
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


# --- the compiled-in table ----------------------------------------------------------------------


def test_every_compiled_in_digest_has_an_arm_of_its_length() -> None:
    assert {ta.ANCHOR_DIGEST, ta.UNMARKED_DIGEST} <= ta.ANCHOR_DIGESTS.keys()
    for name, digest in ta.ANCHOR_DIGESTS.items():
        assert len(ta.anchor_digest_hex(name, b"x")) == digest.hex_chars
    with pytest.raises(TrustAnchorError, match="not compiled into this release"):
        ta.anchor_digest_hex("md5", b"x")


# --- pins ---------------------------------------------------------------------------------------


def test_a_bare_pin_written_today_still_reads_as_sha256(tmp_path: Path) -> None:
    p, fp = _anchor(tmp_path)
    assert parse_anchor_pin(fp) == ("sha256", fp)
    assert parse_anchor_pin(_colons(fp).upper()) == ("sha256", fp)
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), fp), enforcing=True) == fp


@pytest.mark.parametrize("prefix", ["sha256:", "SHA256:", " sha256: "])
def test_a_pin_that_names_sha256_matches(tmp_path: Path, prefix: str) -> None:
    """Red before BACKLOG #3425: a prefixed pin was refused as malformed."""
    p, fp = _anchor(tmp_path)
    assert parse_anchor_pin(prefix + fp) == ("sha256", fp)
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), prefix + fp), enforcing=True) == fp
    assert ta.evaluate_anchor(AnchorSpec("t", "[x]", str(p), prefix + _colons(fp))).pin_ok is True


def test_a_prefixed_pin_that_does_not_match_still_refuses(tmp_path: Path) -> None:
    p, _fp = _anchor(tmp_path)
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), "sha256:" + "0" * 64), enforcing=False)


@pytest.mark.parametrize("marker", ["md5", "sha1", "sha512", "sha3_256", "blake2b"])
def test_a_pin_naming_a_digest_not_compiled_in_is_refused(tmp_path: Path, marker: str) -> None:
    """The marker only chooses among compiled-in digests. Each pin here is the true digest of the
    anchor under its marker, so a marker that reached ``hashlib.new`` would have matched."""
    p, _fp = _anchor(tmp_path)
    true = hashlib.new(marker, p.read_bytes(), usedforsecurity=False).hexdigest()
    pin = f"{marker}:{true}"
    with pytest.raises(TrustAnchorError, match=f"names the digest '{marker}'"):
        parse_anchor_pin(pin)
    spec = AnchorSpec("t", "[x].ca", str(p), pin, "[x].ca_pin")
    with pytest.raises(TrustAnchorError, match=r"^\[x\]\.ca_pin: .*does not support"):
        enforce_anchor(spec, enforcing=False)


@pytest.mark.parametrize("marker", ["sha-256", "SHA3-256"])
def test_a_marker_hashlib_spells_another_way_is_refused(marker: str) -> None:
    with pytest.raises(TrustAnchorError, match="does not support"):
        parse_anchor_pin(f"{marker}:{'ab' * 32}")


def test_a_typo_in_a_bare_pin_reads_as_malformed_not_as_a_digest_name() -> None:
    with pytest.raises(TrustAnchorError, match="must be a SHA-256 hex digest"):
        parse_anchor_pin("3g:" + "ab:" * 31 + "ab")
    assert parse_anchor_pin("sha256 :" + "ab" * 32) == ("sha256", "ab" * 32)


def test_a_connection_pin_naming_an_unknown_digest_refuses_at_load() -> None:
    _check_tls_ca_pin("Rest", "sha256:" + "ab" * 32, "ca.pem")  # the control
    with pytest.raises(ValueError, match="Rest tls_ca_pin: .*names the digest 'md5'"):
        _check_tls_ca_pin("Rest", "md5:" + "ab" * 16, "ca.pem")


@pytest.mark.parametrize("pin", ["sha256:" + "ab" * 31, "sha256:", "sha256:" + "zz" * 32])
def test_a_prefixed_pin_of_the_wrong_shape_is_malformed(pin: str) -> None:
    with pytest.raises(TrustAnchorError, match="must be a SHA-256 hex digest"):
        parse_anchor_pin(pin)


# --- observations -------------------------------------------------------------------------------


async def test_each_observation_names_its_digest(store: MessageStore, tmp_path: Path) -> None:
    """Red before BACKLOG #3425: the row carried a bare fingerprint."""
    p, fp = _anchor(tmp_path)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p))
    await run_anchor_preflight([spec], store, enforcing=True)
    (row,) = await _rows(store, "api_client")
    assert row["event"] == "observed"
    assert (row["algorithm"], row["fingerprint"]) == ("sha256", fp)


async def _seed(store: MessageStore, spec: AnchorSpec, **detail: object) -> None:
    """A row as an earlier release, or another one, wrote it."""
    fields = {"label": spec.label, "setting": spec.setting, "event": "observed", **detail}
    await store.record_audit(AUDIT_ACTION, actor=None, detail=json.dumps(fields))


async def test_an_observation_written_today_still_reads_as_sha256(
    store: MessageStore, tmp_path: Path
) -> None:
    """A row with no ``algorithm`` is a baseline: the same bytes write nothing, a swap writes
    ``changed``."""
    p, fp = _anchor(tmp_path)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p))
    await _seed(store, spec, fingerprint=fp)
    await run_anchor_preflight([spec], store, enforcing=True)
    assert len(await _rows(store, "api_client")) == 1, "an unchanged anchor writes nothing"

    p.write_bytes(_block(b"swapped"))
    await run_anchor_preflight([spec], store, enforcing=True)
    changed = (await _rows(store, "api_client"))[0]
    assert changed["event"] == "changed" and changed["previous"] == fp
    assert changed["algorithm"] == "sha256"


@pytest.mark.parametrize("marker", ["sha512", "md5", 7, None, ["sha256"]])
async def test_an_observation_in_a_digest_not_compiled_in_is_skipped(
    store: MessageStore, tmp_path: Path, marker: object, caplog: pytest.LogCaptureFixture
) -> None:
    """The stored marker never selects a digest. A row naming one the release does not hold is
    skipped, with a WARNING, so it is never compared: with nothing older the check records
    ``observed``, never a false ``changed``."""
    p, fp = _anchor(tmp_path)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p))
    await _seed(store, spec, fingerprint="ab" * 64, algorithm=marker)
    caplog.set_level("WARNING", logger=ta.__name__)
    await run_anchor_preflight([spec], store, enforcing=True)
    latest = (await _rows(store, "api_client"))[0]
    assert latest["event"] == "observed"
    assert (latest["algorithm"], latest["fingerprint"]) == ("sha256", fp)
    assert "they are not compared" in caplog.text


async def test_a_skipped_row_does_not_hide_the_older_baseline(
    store: MessageStore, tmp_path: Path
) -> None:
    """The look-back goes past a row it cannot read, so the anchor is still compared with the
    newest row it can: the same bytes write nothing, a swap writes ``changed``."""
    p, fp = _anchor(tmp_path)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p))
    await _seed(store, spec, fingerprint=fp)
    await _seed(store, spec, fingerprint="ab" * 64, algorithm="sha512")
    await run_anchor_preflight([spec], store, enforcing=True)
    assert len(await _rows(store, "api_client")) == 2, "an unchanged anchor writes nothing"

    p.write_bytes(_block(b"swapped"))
    await run_anchor_preflight([spec], store, enforcing=True)
    changed = (await _rows(store, "api_client"))[0]
    assert changed["event"] == "changed" and changed["previous"] == fp


def _sha512_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """A later release that fingerprints with SHA-512 and keeps SHA-256 compiled in."""
    real = ta.anchor_digest_hex

    def digest_hex(algorithm: str, data: bytes) -> str:
        if algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        return real(algorithm, data)

    monkeypatch.setattr(ta, "ANCHOR_DIGEST", "sha512")
    table = {**ta.ANCHOR_DIGESTS, "sha512": ta.AnchorDigest("SHA-512", 128)}
    monkeypatch.setattr(ta, "ANCHOR_DIGESTS", table)
    monkeypatch.setattr(ta, "anchor_digest_hex", digest_hex)


async def test_a_release_that_changes_the_digest_reads_what_this_one_wrote(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the marker. Under a SHA-512 release a bare pin written today still matches, an
    unchanged anchor writes no false ``changed`` against today's SHA-256 row, and a swap across
    the switch is still a ``changed``."""
    p, fp = _anchor(tmp_path)
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), fp)
    await run_anchor_preflight([spec], store, enforcing=True)  # today's release: sha256 row

    _sha512_release(monkeypatch)
    assert ta.evaluate_anchor(spec).pin_ok is True
    await run_anchor_preflight([spec], store, enforcing=True)
    assert [r["event"] for r in await _rows(store, "api_client")] == ["observed"]

    p.write_bytes(_block(b"swapped"))
    with pytest.raises(TrustAnchorError, match="does not match"):
        await run_anchor_preflight([spec], store, enforcing=True)
    changed = next(r for r in await _rows(store, "api_client") if r["event"] == "changed")
    assert changed["algorithm"] == "sha512"
    assert changed["fingerprint"] == hashlib.sha512(p.read_bytes()).hexdigest()
    assert (changed["previous"], changed["previous_algorithm"]) == (fp, "sha256")
