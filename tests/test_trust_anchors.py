# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 6.7.1 (BACKLOG #285): operator-supplied trust-anchor integrity — the read-only ACL preflight,
the optional SHA-256 pin, the anchor-changed audit event, and dormant-when-unconfigured."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
from pathlib import Path

import pytest

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.trust_anchors import (
    AUDIT_ACTION,
    AnchorSpec,
    TrustAnchorError,
    anchor_fingerprint,
    collect_anchor_specs,
    dacl_is_owner_only,
    enforce_anchor,
    owner_only_from_icacls,
    run_anchor_preflight,
)
from messagefoundry.config.settings import ApiSettings, AuthSettings
from messagefoundry.store import MessageStore

_posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits (icacls is the nt path)")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


def _pem(tmp_path: Path, body: bytes = b"-----BEGIN CERTIFICATE-----\nAAAA\n") -> Path:
    p = tmp_path / "anchor.pem"
    p.write_bytes(body)
    return p


async def _rows(store: MessageStore, label: str | None = None) -> list[dict]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    out = [json.loads(r["detail"]) for r in rows]
    return [d for d in out if label is None or d.get("label") == label]


# --- fingerprint + pin normalization ------------------------------------------------------------


def test_fingerprint_is_sha256_of_bytes(tmp_path: Path) -> None:
    body = b"anchor-pem-bytes"
    p = _pem(tmp_path, body)
    assert anchor_fingerprint(p) == hashlib.sha256(body).hexdigest()


def test_fingerprint_missing_raises_oserror(tmp_path: Path) -> None:
    # A missing/unreadable anchor keeps the engine's existing fail-closed OSError contract.
    with pytest.raises(OSError):
        anchor_fingerprint(tmp_path / "nope.pem")


def test_pin_accepts_colons_and_uppercase(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    fp = hashlib.sha256(b"body").hexdigest()
    # Uppercase, colon-separated — normalized and matched.
    colonized = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2)).upper()
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), colonized), enforcing=True) == fp


def test_malformed_pin_raises(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    with pytest.raises(TrustAnchorError, match="SHA-256 hex digest"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), "not-a-real-pin"), enforcing=False)


# --- pin enforcement (always refuses on mismatch, independent of enforcement) --------------------


def test_pin_match_ok(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    fp = hashlib.sha256(b"body").hexdigest()
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), fp), enforcing=True) == fp


@pytest.mark.parametrize("enforcing", [True, False])
def test_pin_mismatch_always_refuses(tmp_path: Path, enforcing: bool) -> None:
    p = _pem(tmp_path, b"body")
    wrong = hashlib.sha256(b"other").hexdigest()
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), wrong), enforcing=enforcing)


def test_no_pin_is_allowed(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"body")
    # Owner-only tmp file (verified: no broad-group write), no pin → passes.
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)


# --- icacls DACL parser (pure, cross-platform) --------------------------------------------------

_PATH = r"C:\Users\svc\anchor.pem"


def _icacls(*aces: str) -> str:
    first = f"{_PATH} {aces[0]}"
    rest = "\n".join(f"    {a}" for a in aces[1:])
    body = first + ("\n" + rest if rest else "")
    return body + "\n\nSuccessfully processed 1 files; Failed processing 0 files.\n"


def test_icacls_owner_and_privileged_only_is_owner_only() -> None:
    text = _icacls(
        r"NT AUTHORITY\SYSTEM:(I)(F)",
        r"BUILTIN\Administrators:(I)(F)",
        r"DESKTOP-A\svc:(F)",
    )
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_everyone_write_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"Everyone:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_users_modify_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"BUILTIN\Users:(M)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


def test_icacls_users_read_only_is_owner_only() -> None:
    # A CA is public; group READ is fine — only group WRITE is the tamper threat.
    text = _icacls(r"DESKTOP-A\svc:(F)", r"BUILTIN\Users:(RX)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_path_containing_users_is_not_a_false_positive() -> None:
    # The path literally contains \Users; only the owner has an ACE → owner-only.
    text = _icacls(r"DESKTOP-A\svc:(F)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_deny_ace_is_ignored() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"Everyone:(DENY)(W)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is True


def test_icacls_unresolved_broad_sid_write_is_not_owner_only() -> None:
    text = _icacls(r"DESKTOP-A\svc:(F)", r"*S-1-1-0:(W)")
    assert owner_only_from_icacls(text, anchor_path=_PATH) is False


@_posix_only
def test_posix_mode_owner_only(tmp_path: Path) -> None:
    p = _pem(tmp_path, b"x")
    os.chmod(p, 0o600)
    assert dacl_is_owner_only(p) is True
    os.chmod(p, 0o644)  # group/other READ but not write → still owner-only-writable
    assert dacl_is_owner_only(p) is True
    os.chmod(p, 0o666)  # group + other WRITE → not owner-only
    assert dacl_is_owner_only(p) is False
    os.chmod(p, 0o620)  # group WRITE → not owner-only
    assert dacl_is_owner_only(p) is False


# --- ACL enforcement fork: refuse at enforce, warn at warn (dacl monkeypatched) -----------------


def test_group_writable_refuses_at_enforce(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)


def test_group_writable_warns_at_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    fp = enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=False)
    assert fp == hashlib.sha256(b"body").hexdigest()  # started anyway
    assert any("writable by a non-owner" in r.message for r in caplog.records)


def test_indeterminate_dacl_does_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)  # inconclusive → degrade
    assert enforce_anchor(AnchorSpec("t", "[x]", str(p), None), enforcing=True)


# --- spec collection + dormancy -----------------------------------------------------------------


def test_collect_specs_dormant_when_unconfigured() -> None:
    assert collect_anchor_specs(AuthSettings(), ApiSettings()) == []


def test_collect_specs_includes_each_configured_anchor(tmp_path: Path) -> None:
    a = _pem(tmp_path, b"a")
    specs = collect_anchor_specs(
        AuthSettings(oidc_tls_ca_cert_file=str(a), ad_tls_ca_cert_file=str(a)),
        ApiSettings(tls_cert_file=str(a), tls_client_ca_file=str(a), tls_client_ca_pin="ab" * 32),
    )
    labels = {s.label for s in specs}
    assert labels == {"oidc", "ad", "api_client"}
    assert next(s for s in specs if s.label == "api_client").pin == "ab" * 32


# --- central preflight: dormant, baseline, changed, unchanged -----------------------------------


async def test_preflight_dormant_writes_no_audit(store: MessageStore) -> None:
    await run_anchor_preflight([], store, enforcing=True)
    assert await _rows(store) == []


async def test_preflight_baseline_then_unchanged_then_changed(
    store: MessageStore, tmp_path: Path
) -> None:
    p = _pem(tmp_path, b"v1")
    spec = AnchorSpec("api_client", "[api].tls_client_ca_file", str(p), None)

    await run_anchor_preflight([spec], store, enforcing=True)
    rows = await _rows(store, "api_client")
    assert len(rows) == 1 and rows[0]["event"] == "observed"

    # Second load, unchanged → no new row.
    await run_anchor_preflight([spec], store, enforcing=True)
    assert len(await _rows(store, "api_client")) == 1

    # Swap the PEM on disk → the reload seam records a first-class "changed" row.
    p.write_bytes(b"v2-different")
    await run_anchor_preflight([spec], store, enforcing=True)
    rows = await _rows(store, "api_client")
    assert len(rows) == 2
    changed = rows[0]  # most-recent-first
    assert changed["event"] == "changed"
    assert changed["fingerprint"] == hashlib.sha256(b"v2-different").hexdigest()
    assert changed["previous"] == hashlib.sha256(b"v1").hexdigest()


async def test_preflight_pin_mismatch_refuses_at_reload_and_audits(
    store: MessageStore, tmp_path: Path
) -> None:
    p = _pem(tmp_path, b"orig")
    spec = AnchorSpec(
        "oidc", "[auth].oidc_tls_ca_cert_file", str(p), hashlib.sha256(b"orig").hexdigest()
    )
    # First load: pin matches → observed, no raise.
    await run_anchor_preflight([spec], store, enforcing=False)
    assert (await _rows(store, "oidc"))[0]["event"] == "observed"

    # The anchor is swapped out-of-band to a non-matching PEM: reload REFUSES (pin, always), and the
    # change + the pin_mismatch are both audited before the refusal.
    p.write_bytes(b"substituted")
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        await run_anchor_preflight([spec], store, enforcing=False)
    events = [r["event"] for r in await _rows(store, "oidc")]
    assert "changed" in events and "pin_mismatch" in events


async def test_preflight_acl_insecure_audited_at_warn(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(p), None)
    await run_anchor_preflight([spec], store, enforcing=False)  # warn: no raise
    events = {r["event"] for r in await _rows(store, "ad")}
    assert "acl_insecure" in events and "observed" in events


async def test_preflight_acl_insecure_refuses_at_enforce_after_auditing(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _pem(tmp_path, b"body")
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    spec = AnchorSpec("ad", "[auth].ad_tls_ca_cert_file", str(p), None)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        await run_anchor_preflight([spec], store, enforcing=True)
    # The violation is durably audited even though start is refused.
    assert "acl_insecure" in {r["event"] for r in await _rows(store, "ad")}


# --- construction-site enforcement in build_api_ssl_context --------------------------------------


def _self_signed_ca(tmp_path: Path) -> tuple[Path, Path]:
    """A self-signed cert + key PEM (the cert also stands in as the mTLS client-CA bundle)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem = tmp_path / "srv-key.pem"
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca, key_pem


def test_build_api_ssl_context_client_ca_pin_match(tmp_path: Path) -> None:
    ca, key = _self_signed_ca(tmp_path)
    pin = hashlib.sha256(ca.read_bytes()).hexdigest()
    ctx = build_api_ssl_context(
        ApiSettings(
            tls_cert_file=str(ca),
            tls_key_file=str(key),
            tls_client_ca_file=str(ca),
            tls_client_ca_pin=pin,
        ),
        enforcing=True,
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_build_api_ssl_context_client_ca_pin_mismatch_refuses(tmp_path: Path) -> None:
    ca, key = _self_signed_ca(tmp_path)
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        build_api_ssl_context(
            ApiSettings(
                tls_cert_file=str(ca),
                tls_key_file=str(key),
                tls_client_ca_file=str(ca),
                tls_client_ca_pin="00" * 32,
            ),
            enforcing=True,
        )
