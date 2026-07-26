# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 5.0 L2 Phase-0 hardening — tests for the quick-win work packages.

Covers WP-1 (security headers, header-only WS token), WP-2 (WS Origin check), WP-4 (pinned argon2
params), WP-6 (log-injection scrub + UTC + auth.logout audit), WP-7a (request length limits +
webhook egress), WP-7c (file content sniff), and WP-11a (refuse insecure TLS overrides)."""

from __future__ import annotations

import logging
import time
import urllib.request
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.api.models import DeadLetterReplayRequest
from messagefoundry.api.security import _ws_origin_allowed, ws_token
from messagefoundry.auth import passwords
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import AuthSettings, SqlAuth, StoreBackend, StoreSettings
from messagefoundry.logging_setup import ControlCharScrubFilter, configure_logging
from messagefoundry.parsing import sniff
from messagefoundry.parsing.sniff import (
    attachment_mime_agrees,
    b64_head,
    nontext_upload_reason,
)
from messagefoundry.pipeline.alert_sinks import WebhookTransport, _NoRedirectHandler
from messagefoundry.store.sqlserver import connection_string
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.file import _content_matches_declared, _looks_like_hl7

# --- WP-4: argon2 parameters pinned -----------------------------------------


def test_argon2_parameters_are_pinned() -> None:
    h = passwords._hasher
    # Pinned (not library defaults) so a dependency upgrade can't silently change the work factor.
    assert h.time_cost == 3
    assert h.memory_cost == 65536  # 64 MiB — exceeds OWASP's argon2id memory minimum
    assert h.parallelism == 4
    assert h.hash_len == 32
    assert h.salt_len == 16


# --- WP-6: log-injection scrub + UTC ----------------------------------------


def _record(msg: str, args: object = None) -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, "p", 1, msg, args, None)  # type: ignore[arg-type]


def test_control_char_filter_neutralizes_crlf() -> None:
    rec = _record("legit line\r\nINJECTED forged line")
    assert ControlCharScrubFilter().filter(rec) is True
    out = rec.getMessage()
    assert "\n" not in out and "\r" not in out
    assert "\\n" in out and "\\r" in out  # escaped, single-line


def test_control_char_filter_scrubs_interpolated_args() -> None:
    rec = _record("peer said %s", ("a\nb\x00c",))
    ControlCharScrubFilter().filter(rec)
    out = rec.getMessage()
    assert "\n" not in out and "\x00" not in out
    assert "a\\nb\\x00c" in out


def test_control_char_filter_leaves_clean_message_lazy() -> None:
    rec = _record("count=%d", (5,))
    ControlCharScrubFilter().filter(rec)
    assert rec.args == (5,)  # untouched — lazy formatting preserved for clean messages
    assert rec.getMessage() == "count=5"


def test_configure_logging_uses_utc_timestamps() -> None:
    configure_logging("INFO")
    root = logging.getLogger()
    formatter = root.handlers[0].formatter
    assert formatter is not None and formatter.converter is time.gmtime


# --- WP-2: WebSocket Origin allowlist ---------------------------------------


def _fake_ws(origin: str | None, allowed: tuple[str, ...]) -> SimpleNamespace:
    state = SimpleNamespace(ws_allowed_origins=allowed)
    headers: dict[str, str] = {} if origin is None else {"origin": origin}
    return SimpleNamespace(headers=headers, app=SimpleNamespace(state=state))


def test_ws_origin_allows_native_client_without_origin() -> None:
    assert _ws_origin_allowed(_fake_ws(None, ())) is True


def test_ws_origin_rejects_browser_origin_by_default() -> None:
    assert _ws_origin_allowed(_fake_ws("https://evil.example", ())) is False


def test_ws_origin_honors_allowlist() -> None:
    assert _ws_origin_allowed(_fake_ws("https://ok.example", ("https://ok.example",))) is True
    assert _ws_origin_allowed(_fake_ws("https://evil.example", ("https://ok.example",))) is False


# --- WP-1: header-only WS token + security headers --------------------------


def test_ws_token_is_header_only() -> None:
    assert ws_token(SimpleNamespace(headers={"Authorization": "Bearer abc"})) == "abc"  # type: ignore[arg-type]
    assert ws_token(SimpleNamespace(headers={})) is None  # type: ignore[arg-type]


async def test_security_headers_present_on_response() -> None:
    transport = httpx.ASGITransport(app=create_app(allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"
    # No TLS on the request → no HSTS (it would be misleading over plain http).
    assert "strict-transport-security" not in r.headers


# --- WP-6: auth.logout audited ----------------------------------------------


async def test_logout_emits_audit_event() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        boot = await service.initialize()
        assert boot is not None
        out = await service.login("admin", boot.password)
        assert out.ok and out.token is not None
        await service.logout(out.token, actor="admin")
        actions = [row["action"] for row in await store.list_audit()]
        assert "auth.logout" in actions
    finally:
        await store.close()


# --- WP-7a: request length limits + webhook egress --------------------------


def test_dead_letter_replay_request_bounds_length() -> None:
    DeadLetterReplayRequest(channel_id="x" * 256)  # at the cap — fine
    with pytest.raises(ValidationError):
        DeadLetterReplayRequest(channel_id="x" * 257)


def test_webhook_rejects_non_http_scheme() -> None:
    # Non-http(s) schemes are refused at construction (urllib would otherwise honour file:/ftp:).
    with pytest.raises(ValueError, match="must be http or https"):
        WebhookTransport("ftp://host/hook")


def test_webhook_rejects_plaintext_http_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # ASVS 12.2.1: a plaintext http:// webhook target is refused at construction (no insecure
    # fallback) unless the explicit MEFOR_ALLOW_INSECURE_TLS dev escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="plaintext http"):
        WebhookTransport("http://hooks.example/x")


def test_webhook_allows_plaintext_http_with_insecure_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With the explicit escape set, a plaintext target constructs (trusted-network dev only).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    t = WebhookTransport("http://hooks.example/x")
    assert t.url == "http://hooks.example/x"


def test_webhook_rejects_host_outside_allowlist() -> None:
    t = WebhookTransport("https://evil.example/hook", allowed_hosts=("ok.example",))
    with pytest.raises(ValueError):
        t._post({"type": "t", "connection": "c"})


def test_webhook_no_redirect_handler_refuses_redirects() -> None:
    handler = _NoRedirectHandler()
    req = urllib.request.Request("http://a/x")
    assert handler.redirect_request(req, None, 302, "Found", {}, "http://b/y") is None  # type: ignore[arg-type]


# --- WP-7c: file content sniff ----------------------------------------------


def test_looks_like_hl7_accepts_valid_headers() -> None:
    assert _looks_like_hl7(b"MSH|^~\\&|APP")
    assert _looks_like_hl7(b"\x0bMSH|^~\\&|APP")  # MLLP start byte
    assert _looks_like_hl7(b"\xef\xbb\xbfMSH|^~\\&|APP")  # UTF-8 BOM
    assert _looks_like_hl7(b"  \r\nFHS|^~\\&|APP")  # batch file header, leading whitespace
    assert _looks_like_hl7(b"BHS|^~\\&|APP")


def test_looks_like_hl7_rejects_non_hl7() -> None:
    assert not _looks_like_hl7(b"hello world, not hl7")
    assert not _looks_like_hl7(b"")
    assert not _looks_like_hl7(b"\x00\x01\x02\x03binary")
    assert not _looks_like_hl7(b"PID|1||100")  # PID is not a leading header segment


# --- WP245 5.2.2: accept-time magic-byte content check per declared content_type ----------


def test_content_matches_declared_hl7v2_and_none() -> None:
    # HL7V2 and None both use the MSH/FHS/BHS head sniff; None keeps file.py's historical None->hl7v2.
    assert _content_matches_declared(ContentType.HL7V2, b"MSH|^~\\&|A")
    assert not _content_matches_declared(ContentType.HL7V2, b"\x00\x01not hl7")
    assert _content_matches_declared(None, b"MSH|^~\\&|A")  # None -> hl7v2 (file.py semantics)
    assert not _content_matches_declared(None, b"garbage")


def test_content_matches_declared_x12_tolerates_codec_leading_noise() -> None:
    assert _content_matches_declared(ContentType.X12, b"ISA*00*          *00*")
    assert _content_matches_declared(ContentType.X12, b"  \xef\xbb\xbfISA*00*")  # ws + UTF-8 BOM
    assert _content_matches_declared(
        ContentType.X12, b"\x0b\x0cISA*00*"
    )  # MLLP/FF noise the codec tolerates
    assert not _content_matches_declared(ContentType.X12, b"MSH|^~\\&|A")  # HL7 on an x12 inbound


# --- 5.2.2 hoist: sniffers moved to parsing.sniff, re-exported from transports.file ----------


def test_sniffers_hoisted_to_parsing_sniff_and_reexported() -> None:
    # The pure magic-byte sniffers now live in parsing.sniff (so the leaf uploads.py can reuse them
    # without importing a transport); transports.file re-exports the SAME objects for remotefile.py +
    # existing tests, so an import from either path resolves to one implementation.
    assert _looks_like_hl7 is sniff._looks_like_hl7
    assert _content_matches_declared is sniff._content_matches_declared


# --- 1.3.4/5.2.2 attachment MIME-vs-magic downgrade -----------------------------------------


def test_attachment_mime_agrees_matches_and_contradicts() -> None:
    # A sniffable family agrees only when its magic bytes lead the document.
    assert attachment_mime_agrees("image/png", b"\x89PNG\r\n\x1a\n rest")
    assert not attachment_mime_agrees("image/png", b"%PDF-1.7 not a png")
    assert attachment_mime_agrees("application/pdf", b"%PDF-1.4 body")
    assert not attachment_mime_agrees("application/pdf", b"\x89PNG\r\n\x1a\n")
    assert attachment_mime_agrees("image/jpeg", b"\xff\xd8\xff\xe0")
    assert attachment_mime_agrees("image/gif", b"GIF89a...")
    assert attachment_mime_agrees("image/tiff", b"II*\x00")
    assert attachment_mime_agrees("application/zip", b"PK\x03\x04")
    # docx et al. are ZIP containers — a docx MIME with ZIP magic agrees; with non-ZIP bytes it does not.
    assert not attachment_mime_agrees("application/zip", b"not a zip")


def test_attachment_mime_agrees_structured_syntax_and_params() -> None:
    # +xml / +json structured-syntax suffixes and explicit xml/json/svg MIMEs sniff the first non-ws byte.
    assert attachment_mime_agrees("application/xml", b"  <?xml version='1.0'?>")
    assert attachment_mime_agrees("image/svg+xml", b"\xef\xbb\xbf<svg/>")  # BOM + <
    assert not attachment_mime_agrees("application/xml", b"NOT xml")
    assert attachment_mime_agrees("application/fhir+json", b'{"resourceType":"Patient"}')
    assert attachment_mime_agrees("application/json", b"[1,2,3]")
    assert not attachment_mime_agrees("application/json", b"<html>")
    # A MIME with parameters is normalized to type/subtype before the family lookup.
    assert not attachment_mime_agrees("image/png; charset=binary", b"%PDF")


def test_attachment_mime_agrees_accepts_unsniffable_and_blank() -> None:
    # No reliable leading signature → accept the declared label unchecked (octet-stream, text, dicom, …).
    assert attachment_mime_agrees("application/octet-stream", b"\x00\x01\x02")
    assert attachment_mime_agrees("text/plain", b"\x00 anything")
    assert attachment_mime_agrees("application/dicom", b"\x00" * 132)
    assert attachment_mime_agrees("", b"whatever")  # nothing declared to contradict
    assert attachment_mime_agrees(None, b"whatever")


def test_b64_head_decodes_leading_bytes() -> None:
    import base64 as _b64

    png = b"\x89PNG\r\n\x1a\n" + b"payload" * 100
    b64 = _b64.b64encode(png).decode("ascii")
    assert b64_head(b64).startswith(b"\x89PNG\r\n\x1a\n")
    # Tolerant of embedded whitespace/newlines (as OBX-5.5 base64 may carry).
    wrapped = "\n".join(b64[i : i + 8] for i in range(0, len(b64), 8))
    assert b64_head(wrapped).startswith(b"\x89PNG\r\n\x1a\n")
    # An empty / whitespace-only prefix decodes to b"" (the caller then treats a claimed magic as a
    # contradiction and downgrades — conservative).
    assert b64_head("") == b""
    assert b64_head("   \n\t ") == b""


# --- 14.2.8 text-only upload gate (nontext_upload_reason) -----------------------------------


def test_nontext_upload_reason_rejects_binary_containers() -> None:
    # ASVS 14.2.8: metadata-bearing containers are rejected by their leading magic bytes (the reason names
    # the family; the caller maps a non-None reason to HTTP 415). DOCX rides the ZIP magic (PK\x03\x04).
    assert nontext_upload_reason(b"%PDF-1.7\n%stuff") is not None  # PDF
    assert nontext_upload_reason(b"\x89PNG\r\n\x1a\n\x00\x00") is not None  # PNG
    assert nontext_upload_reason(b"\xff\xd8\xff\xe0\x00\x10JFIF") is not None  # JPEG
    assert nontext_upload_reason(b"PK\x03\x04\x14\x00\x00\x00word/") is not None  # ZIP / DOCX
    assert nontext_upload_reason(b"GIF89a\x01\x00") is not None  # GIF
    assert nontext_upload_reason(b"II*\x00\x08\x00") is not None  # TIFF


def test_nontext_upload_reason_rejects_nul_and_control_dense() -> None:
    # ASVS 14.2.8: a NUL byte or a high density of C0 control bytes (not the allowed terminators) is
    # rejected even without a magic signature.
    assert nontext_upload_reason(b"plain start\x00then binary") is not None  # NUL
    assert nontext_upload_reason(bytes(range(1, 32)) * 40) is not None  # control-dense blob


def test_nontext_upload_reason_accepts_text_logs() -> None:
    # ASVS 14.2.8: the permitted text formats pass (None = admissible). HL7 leans on \r segment
    # terminators + MLLP frame bytes, all in the allowed control set.
    assert nontext_upload_reason(b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rPID|1\r") is None
    assert nontext_upload_reason(b"\x0bMSH|^~\\&|A\rPID|1\r\x1c\r") is None  # MLLP-framed
    assert nontext_upload_reason(b"a plain diagnostic line\n") is None  # .txt
    assert nontext_upload_reason(b"<root><child/></root>") is None  # .xml
    assert nontext_upload_reason(b"\xef\xbb\xbf<root/>") is None  # UTF-8 BOM + xml
    assert nontext_upload_reason(b"") is None  # empty body has nothing binary to reject


def test_content_matches_declared_dicom_requires_part10_preamble() -> None:
    # TRAP GUARD: a real Part-10 object (128-byte preamble + DICM) passes; a truncated / non-DICOM
    # body is quarantined. Every DICOM object the engine produces/parses carries the magic.
    assert _content_matches_declared(ContentType.DICOM, b"\x00" * 128 + b"DICM" + b"rest")
    assert not _content_matches_declared(ContentType.DICOM, b"DICM" + b"x" * 3)  # len < 132
    assert not _content_matches_declared(ContentType.DICOM, b"%PDF-1.7 not dicom")


def test_content_matches_declared_json_and_xml_handle_bom_and_ws() -> None:
    assert _content_matches_declared(ContentType.JSON, b'{"a":1}')
    assert _content_matches_declared(ContentType.JSON, b"  [1,2]")
    assert _content_matches_declared(ContentType.JSON, b'\xef\xbb\xbf  {"a":1}')  # BOM + ws
    assert not _content_matches_declared(ContentType.JSON, b"<x/>")
    assert not _content_matches_declared(ContentType.JSON, b"not json")
    assert _content_matches_declared(ContentType.XML, b'<?xml version="1.0"?>')
    assert _content_matches_declared(ContentType.XML, b"\xef\xbb\xbf<root/>")
    assert not _content_matches_declared(ContentType.XML, b'{"a":1}')


def test_content_matches_declared_signatureless_types_accept_unchecked() -> None:
    # BINARY must stay unchecked by design (opaque bytes, ADR 0028); TEXT is arbitrary. Neither has a
    # reliable leading signature, so both accept unchecked — the pipeline parser is the real validator.
    assert _content_matches_declared(ContentType.BINARY, b"\x00\x01\xff arbitrary pdf")
    assert _content_matches_declared(ContentType.TEXT, b"\x00 anything")


def test_content_matches_declared_fhir_uses_json_sniff() -> None:
    # FHIR is "HL7 FHIR JSON", so it shares the JSON leading-{/[ sniff (tolerating BOM + whitespace):
    # a JSON-shaped body passes; a PDF / XML / bare-text body on a content_type=fhir inbound is rejected
    # (quarantined at the call site) — driving ASVS 5.2.2 to full Pass over the prior unchecked accept.
    assert _content_matches_declared(ContentType.FHIR, b'{"resourceType":"Patient"}')
    assert _content_matches_declared(ContentType.FHIR, b"  [{}]")  # a bundle-ish array, leading ws
    assert _content_matches_declared(
        ContentType.FHIR, b'\xef\xbb\xbf{"resourceType":"Bundle"}'
    )  # BOM
    assert not _content_matches_declared(ContentType.FHIR, b"%PDF-1.7 not fhir")
    assert not _content_matches_declared(ContentType.FHIR, b"<Patient/>")  # XML, not FHIR JSON
    assert not _content_matches_declared(ContentType.FHIR, b"not-json-shaped")


# --- WP-11a: refuse insecure TLS overrides ----------------------------------


def test_sqlserver_connection_string_refuses_weak_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    s = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db",
        database="mf",
        username="svc",
        password="p",
        auth=SqlAuth.SQL,
        trust_server_certificate=True,
    )
    with pytest.raises(ValueError):
        connection_string(s)
    # The explicit dev escape permits it.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert "TrustServerCertificate=yes" in connection_string(s)


def test_ldap_authenticator_refuses_disabled_cert_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    s = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_user_search_base="DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
        ad_bind_password="secret",
        ad_tls_verify=False,
    )
    with pytest.raises(LdapError):
        LdapAuthenticator(s)
    # With the dev escape, construction is allowed (it only warns; no bind happens here).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    LdapAuthenticator(s)
