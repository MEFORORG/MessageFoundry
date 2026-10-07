# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Operator attachment read/download surface (#149, ADR 0105 Phase 3b) + its ASVS 1.3.4 serve-time
neutralization.

The store read method (``attachments_for``), the ``MessageDetail.attachments`` metadata list, and the
audited, PHI-gated ``GET /messages/{message_id}/attachments/{attachment_id}`` download endpoint. Covers
the byte round-trip, the RBAC gate (Viewer → 403), the channel-scope + linkage 404s (the security
crux: never pull a shared content-addressed blob unlinked to an in-scope message), the audit chain
(``record_view`` + ``attachment_download`` with NO bytes), and the Content-Type / Content-Disposition.

**ASVS 1.3.4 (inert-type allow-list + sandbox CSP).** The stored ``content_type`` is a verbatim,
attacker-influenced OBX-5.2 label. The serve-time control is *neutralize at serve*, never a sanitizing
rewrite of the stored clinical bytes (ADR 0105 Approach B keeps the OBX-5.5 value verbatim): the label is
DECLARED only when it exactly names one of the inert types on ``_INERT_ATTACHMENT_TYPES``, and everything
else — browser-active, unknown or malformed — is declared ``application/octet-stream``. The match is
case-folded, so ``Image/SVG+XML`` is treated exactly like ``image/svg+xml``. The same table supplies the
download-name extension (default ``.bin``), so no ``.svg``/``.html``/``.hta`` name is produced and the
served filename no longer depends on ``mimetypes``, which reads the Windows registry. Every download
response carries ``Content-Security-Policy: default-src 'none'; sandbox``, **including the console's
``/ui`` delegate**, where two ``/ui``-scoped middlewares would otherwise overwrite a route-level CSP with
a console policy that has no ``sandbox``.

The allow-list is what makes these tests meaningful in BOTH directions. A table where every input
downgrades would pass against a function that returns the constant, so ``_PASS_THROUGH_LABELS`` is the
negative control and is asserted just as hard.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import mimetypes
import traceback
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import (
    _ATTACHMENT_CSP,
    _DEFAULT_ATTACHMENT_EXT,
    _INERT_ATTACHMENT_TYPES,
    _safe_attachment_content_type,
)
from messagefoundry.api.svg_sanitize import SvgRejected
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"  # ≥15, no vendor terms — satisfies the ASVS policy
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

# A synthetic "document" (fake PDF bytes) → base64, exactly as Approach B carries the verbatim OBX-5.5
# value into the attachment substrate. The download must decode this back to DOC byte-for-byte.
DOC = b"%PDF-1.4\nsynthetic document body \x00\x01\x02 not real PHI\n%%EOF\n"
DOC_B64 = base64.b64encode(DOC).decode("ascii")

#: Labels whose specifications describe an executable or markup representation — none of them is on the
#: inert allow-list, so every one must serve as the generic binary type. The first block is the family the
#: retired four-token refusal list caught (``html``/``xml``/``script``/``svg`` + ``multipart``), including
#: the vectors an exact-subtype or ``+xml``-suffix test misses (``application/x-javascript``, ``image/svg``
#: with no ``+xml``, ``application/xml-dtd``, ``text/x-html``) and the MIXED-CASE spellings the token
#: grammar admits verbatim.
#:
#: The second block is what the refusal list DID NOT catch, and is the reason the classifier was inverted:
#: each of these passes all four tokens and the ``multipart`` rule. ``application/hta`` is the decisive
#: one — a scriptable HTML Application whose registry-derived extension is ``.hta``. Their presence here
#: is a specification claim about the types, NOT a browser measurement: nobody has exercised a browser.
#: The allow-list is what makes that distinction stop mattering, because a type nobody thought of is
#: refused for the same reason a listed one is — it is simply not on the list.
_BROWSER_ACTIVE_LABELS = (
    # caught by the retired four-token refusal list
    "image/svg+xml",
    "text/html",
    "Image/SVG+XML",
    "TEXT/HTML",
    "text/HtMl",
    "application/xhtml+xml",
    "text/xml",
    "application/xml",
    "application/javascript",
    "text/javascript",
    "application/ecmascript",
    "application/x-javascript",
    "application/rss+xml",
    "image/svg",
    "application/xml-dtd",
    "multipart/x-mixed-replace",
    "text/x-html",
    # MISSED by the retired four-token refusal list
    "application/hta",
    "text/x-component",
    "application/x-xpinstall",
    "application/x-shockwave-flash",
    "application/x-msdownload",
)

#: Shapes that never reach the allow-list at all because the MIME *shape* screen rejects them first: a
#: parameterized type (the screen admits no ``;``), and a header-splitting attempt. Both must land on the
#: same generic type, so the two screens compose rather than leaving a gap between them.
_MALFORMED_LABELS = (
    "image/svg+xml; charset=utf-8",
    "text/plain; charset=utf-8",
    "text/html\r\nX-Evil: 1",
)

#: Inert labels that must keep passing through under their own type — the operator still gets a usable
#: download hint. **This is the negative control.** A downgrade table alone would pass against a
#: ``_safe_attachment_content_type`` that returned ``application/octet-stream`` unconditionally; these
#: cases are what force the allow-list to actually allow.
_PASS_THROUGH_LABELS = (
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/dicom",
    "application/json",
    "text/plain",
    "text/csv",
)
#: Leading magic so a CORRECTLY-labelled inert attachment agrees with its declared MIME (ASVS 5.2.2):
#: the download-side MIME-vs-magic check downgrades a sniffable label whose bytes contradict it.
#: dicom/text/bmp carry no leading signature in that table, so they need none.
_PASS_THROUGH_MAGIC: dict[str, bytes] = {
    "application/pdf": b"%PDF-",
    "image/png": bytes.fromhex("89504e470d0a1a0a"),  # PNG signature
    "image/jpeg": bytes.fromhex("ffd8ff"),
    "image/gif": b"GIF89a",
    "application/json": b"{",  # leading-brace sniff, not a magic-byte family
}

#: The extension the SHIPPED allow-list gives each served type. Pinned as LITERALS on purpose. The old
#: assertions computed the expectation with ``mimetypes.guess_extension`` — the very call the endpoint
#: made — so they agreed with the endpoint by construction and would have agreed with a wrong endpoint
#: too. The extension is now a property of the product rather than of the host, so there is nothing
#: machine-local left to compute and a literal is the honest expectation.
_SERVED_EXT: dict[str, str] = {
    "application/dicom": ".dcm",
    "application/json": ".json",
    "application/pdf": ".pdf",
    "image/bmp": ".bmp",
    "image/gif": ".gif",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tif",
    "text/csv": ".csv",
    "text/plain": ".txt",
}
#: Wraps a marker text as a well-formed SVG drawing, for a case that needs an SVG the route can parse.
_SVG_OPEN = b'<svg xmlns="http://www.w3.org/2000/svg"><title>'
_SVG_CLOSE = b"</title></svg>"
#: What every non-allow-listed type gets, refused or merely unknown.
_OCTET = "application/octet-stream"
_OCTET_EXT = ".bin"


def _disposition(ref: str, ext: str) -> str:
    """The exact ``Content-Disposition`` the route must serve for ``ref`` at ``ext``."""
    return f'attachment; filename="attachment-{ref[:16]}{ext}"'


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "attach_api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def _seed_streaming(
    engine: Engine, *, channel_id: str = "ch1", content_type: str = "application/pdf"
) -> tuple[str, str]:
    """Put a detached document + a message that links it (the ingress two-object commit). Returns
    ``(message_id, attachment_ref)``."""
    ref = await engine.store.put_attachment([DOC_B64], content_type)
    mid = await engine.store.enqueue_ingress(
        channel_id=channel_id, raw=ADT, control_id="MSG1", attachment_refs=[ref]
    )
    return mid, ref


async def _seed_labelled(
    engine: Engine, content_type: str, marker: str, *, prefix: bytes = b"", suffix: bytes = b""
) -> tuple[str, str]:
    """Seed one document carrying ``content_type``, with bytes UNIQUE to ``marker``.

    Attachments are content-addressed and deduplicated: ``put_attachment`` on bytes that already exist
    returns the existing ref and writes nothing, so the FIRST writer's ``content_type`` governs every
    later linkage of the same body. A per-MIME table that reused one document would therefore collapse
    onto the first label and assert nothing — every case must seed its own bytes."""
    doc = base64.b64encode(
        prefix + f"synthetic document {marker} not real PHI".encode() + suffix
    ).decode("ascii")
    ref = await engine.store.put_attachment([doc], content_type)
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    return mid, ref


def _base_media_type(response: httpx.Response) -> str:
    """The served media type without parameters — Starlette appends ``; charset=utf-8`` to any
    ``text/*``, so an equality assertion has to compare the type alone."""
    return response.headers["content-type"].split(";")[0].strip()


# --- store: attachments_for --------------------------------------------------


async def test_attachments_for_returns_linked_metadata(engine: Engine) -> None:
    mid, ref = await _seed_streaming(engine)
    rows = await engine.store.attachments_for(mid)
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["attachment_id"] == ref
    assert row["content_type"] == "application/pdf"
    # total_bytes is the reconstructed (verbatim base64) size the store recorded, never a body read.
    assert row["total_bytes"] == len(DOC_B64.encode("utf-8"))


async def test_attachments_for_empty_for_normal_message(engine: Engine) -> None:
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    assert await engine.store.attachments_for(mid) == []


# --- API: MessageDetail.attachments ------------------------------------------


async def test_message_detail_lists_attachments(engine: Engine, client: httpx.AsyncClient) -> None:
    mid, ref = await _seed_streaming(engine)
    detail = (await client.get(f"/messages/{mid}")).json()
    assert len(detail["attachments"]) == 1
    att = detail["attachments"][0]
    assert att["id"] == ref
    assert att["content_type"] == "application/pdf"
    assert att["total_bytes"] == len(DOC_B64.encode("utf-8"))


async def test_message_detail_attachments_empty_for_normal_message(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    assert (await client.get(f"/messages/{mid}")).json()["attachments"] == []


# --- API: download endpoint --------------------------------------------------


async def test_download_round_trips_to_original_bytes(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    # The decoded download is byte-for-byte the original document (the security invariant (f)).
    assert r.content == DOC
    assert r.headers["content-type"].startswith("application/pdf")
    # 5.4.1 re-score: pin the FULL served Content-Disposition, not just a substring — the fixed
    # 'attachment; filename="attachment-' prefix + the sha256 content address cut to 16 hex + the
    # allow-list's extension, quoted; no user/attacker text reaches the header
    # (api/app.py:_attachment_filename). Seeded straight through the store, so this holds WITHOUT
    # enabling the opt-in stream_threshold_bytes. The extension is a literal now, not a mimetypes call.
    assert r.headers["content-disposition"] == _disposition(ref, ".pdf")


async def test_download_audits_view_and_download_before_returning(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    # record_view → a per-message 'viewed' event; attachment_download → a tamper-evident audit row.
    assert any(e["event"] == "viewed" for e in await engine.store.events_for(mid))
    audit = await engine.store.list_audit()
    dl = [a for a in audit if a["action"] == "attachment_download"]
    assert len(dl) == 1
    # The audit detail names the id pair but NEVER the bytes/base64 (security invariant (b)/(c)).
    detail = dl[0]["detail"] or ""
    assert mid in detail and ref in detail
    assert DOC_B64 not in detail
    # A served download is never also recorded as a refusal (BACKLOG #2387).
    assert not [a for a in audit if a["action"] == "attachment_download_refused"]


async def test_download_never_logs_bytes(
    engine: Engine, client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    mid, ref = await _seed_streaming(engine)
    with caplog.at_level(logging.DEBUG):
        r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert DOC_B64 not in blob
    assert "synthetic document body" not in blob


async def test_download_content_type_defaults_when_not_clean_mime(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # A hostile/attacker-influenced content_type (CRLF header-injection attempt) is never trusted into
    # the response header — it is served as the generic binary type (security invariant on the header).
    ref = await engine.store.put_attachment([DOC_B64], "text/html\r\nX-Evil: 1")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    # 5.4.2 re-score: a non-allowlisted / injection-bearing MIME is served as the generic binary
    # type, never the attacker value verbatim (_safe_attachment_content_type), and no injected
    # header survives.
    assert r.headers["content-type"] == "application/octet-stream"
    assert "X-Evil" not in r.headers
    # The served-filename control still holds on a rejected MIME: the extension is the allow-list's
    # default, never the attacker text and never a host-registry lookup.
    assert r.headers["content-disposition"] == _disposition(ref, _OCTET_EXT)


async def test_download_downgrades_mislabelled_active_mime_to_octet_stream(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # ASVS 1.3.4/5.2.2: even a TOKEN-CLEAN stored MIME is sender-influenced (OBX-5.2). If it names a
    # sniffable family (image/png) whose magic the reconstructed bytes contradict (DOC leads with %PDF),
    # the download is served as the generic octet-stream so a mislabelled active-content payload can't be
    # rendered as its claimed inert type. The bytes still round-trip byte-for-byte (only the MIME shifts).
    ref = await engine.store.put_attachment([DOC_B64], "image/png")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.content == DOC  # bytes unchanged; only the served MIME is downgraded


# --- ASVS 1.3.4: browser-active downgrade + sandbox CSP ----------------------


@pytest.mark.parametrize("label", _BROWSER_ACTIVE_LABELS)
async def test_browser_active_label_is_downgraded_to_octet_stream(
    engine: Engine, client: httpx.AsyncClient, label: str
) -> None:
    """A label a browser would execute or render as markup is NEVER served verbatim.

    Mechanically: the served ``Content-Type`` is exactly ``application/octet-stream``, and the served
    filename carries the allow-list's ``.bin`` default — so no ``.svg``/``.html``/``.hta``/``.js`` name is
    produced either. Mixed-case vectors are in the table because the token grammar admits uppercase and
    the allow-list lookup is case-folded, so ``Image/SVG+XML`` must resolve exactly as ``image/svg+xml``
    does. An SVG label is seeded as a well-formed drawing, so these rows also cover the declared type
    of a SANITIZED copy (ADR 0105 amendment 2026-09-28); the non-markup SVG-label case is
    ``test_svg_label_on_non_markup_bytes_is_served_unchanged``."""
    prefix, suffix = (_SVG_OPEN, _SVG_CLOSE) if "svg" in label.casefold() else (b"", b"")
    mid, ref = await _seed_labelled(engine, label, marker=label, prefix=prefix, suffix=suffix)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == _OCTET
    assert r.headers["content-disposition"] == _disposition(ref, _OCTET_EXT)
    assert (
        not r.headers["content-disposition"].rstrip('"').endswith((".svg", ".html", ".xml", ".hta"))
    )


@pytest.mark.parametrize("label", _PASS_THROUGH_LABELS)
async def test_inert_label_passes_through_unchanged(
    engine: Engine, client: httpx.AsyncClient, label: str
) -> None:
    """THE NEGATIVE CONTROL. The downgrade is targeted, not a blanket octet-stream: a correctly-labelled
    inert type still serves as itself and still supplies the download-name extension, so operators keep a
    usable hint. Without these cases the downgrade table above would pass against a
    ``_safe_attachment_content_type`` that returned the constant.

    Sniffable families (pdf/png/jpeg/gif/json) are seeded with matching magic so the 5.2.2 MIME-vs-magic
    check agrees; dicom/text carry no signature in that table."""
    mid, ref = await _seed_labelled(
        engine, label, marker=label, prefix=_PASS_THROUGH_MAGIC.get(label, b"")
    )
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == label
    assert r.headers["content-disposition"] == _disposition(ref, _SERVED_EXT[label])


async def test_overlong_label_is_downgraded(engine: Engine, client: httpx.AsyncClient) -> None:
    """The token grammar is unbounded and the stored column has no length check, so an arbitrarily long
    attacker label would otherwise be echoed into a response header."""
    mid, ref = await _seed_labelled(engine, "application/" + "a" * 300, marker="overlong")
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert _base_media_type(r) == _OCTET
    assert r.headers["content-disposition"] == _disposition(ref, _OCTET_EXT)


# --- ASVS 1.3.4: the classifier is an ALLOW-LIST, and the extension is ours ---------------------


@pytest.mark.parametrize("label", _BROWSER_ACTIVE_LABELS + _MALFORMED_LABELS)
def test_only_allowlisted_types_are_declared(label: str) -> None:
    """Unit-level twin of the download parametrization, at the function the whole control rests on.

    Every label here is refused for ONE reason: it is not on ``_INERT_ATTACHMENT_TYPES``. That is the
    inversion. The retired control listed what to refuse, which asked review to prove no further
    executable type existed; ``application/hta`` in the table above is the counterexample that shows the
    negative could not be proved. Adding ``hta`` to a refusal list would have closed one vector and left
    the shape of the defect intact."""
    assert _safe_attachment_content_type(label) == _OCTET


@pytest.mark.parametrize("label", sorted(_INERT_ATTACHMENT_TYPES))
def test_allowlisted_types_are_declared_verbatim(label: str) -> None:
    """The negative control at unit level, over the WHOLE shipped allow-list: every listed type is
    declared as itself. Driven off ``_INERT_ATTACHMENT_TYPES`` rather than ``_PASS_THROUGH_LABELS`` so
    entries the HTTP table cannot exercise (``image/tiff`` and ``image/bmp`` need magic bytes the seeded
    document does not carry) are still covered here."""
    assert _safe_attachment_content_type(label) == label


@pytest.mark.parametrize(
    "label",
    [
        "application/pdf-javascript",  # CONTAINS an allow-listed type
        "xapplication/pdf",
        "application/pdf+xml",
        "text/plain-html",
        "image/png2",
    ],
)
def test_allowlist_match_is_exact_not_substring(label: str) -> None:
    """The allow-list is matched EXACTLY, never as a substring or a prefix.

    The refusal list it replaced matched substrings on purpose, and that reasoning was right for a
    refusal list: near-miss spellings of active types are dense. Turned around, the same density is a
    hazard — a substring match in the allow direction would hand ``application/pdf-javascript`` a pass
    because it contains ``application/pdf``. This pins the direction of the match, not just its result."""
    assert _safe_attachment_content_type(label) == _OCTET


@pytest.mark.parametrize("label", ["Text/Plain", "IMAGE/PNG", "aPPlicaTion/PDF"])
def test_allowlist_lookup_is_case_folded(label: str) -> None:
    """Browsers match media types case-insensitively, so the lookup folds case — and what is SERVED is
    the canonical key from the table, not the stored spelling, so no attacker-influenced byte reaches the
    ``Content-Type`` header at all."""
    served = _safe_attachment_content_type(label)
    assert served == label.casefold()
    assert served in _INERT_ATTACHMENT_TYPES


def test_none_and_blank_content_type_are_declared_generic() -> None:
    """A missing OBX-5.2 label declares nothing, so it gets the generic type like any other non-match."""
    assert _safe_attachment_content_type(None) == _OCTET
    assert _safe_attachment_content_type("") == _OCTET
    assert _safe_attachment_content_type("   ") == _OCTET


def test_served_extension_table_covers_the_shipped_allowlist() -> None:
    """Drift guard on the literals above: a lane that adds a type to ``_INERT_ATTACHMENT_TYPES`` has to
    pin its extension here too, so ``_SERVED_EXT`` cannot quietly stop covering the shipped list."""
    assert set(_SERVED_EXT) == set(_INERT_ATTACHMENT_TYPES)
    assert _SERVED_EXT == _INERT_ATTACHMENT_TYPES
    assert _DEFAULT_ATTACHMENT_EXT == _OCTET_EXT


def test_app_module_no_longer_imports_mimetypes() -> None:
    """The served filename must not be a property of the HOST.

    ``mimetypes.guess_extension`` reads the Windows registry, so the extension the engine served was
    whatever the machine happened to have registered — measured on a Windows host,
    ``mimetypes.guess_extension("application/hta")`` returns ``.hta``. The module no longer imports the
    library at all, which is the strongest form of the assertion."""
    from messagefoundry.api import app as app_module

    assert not hasattr(app_module, "mimetypes")


async def test_served_extension_does_not_depend_on_mimetypes(
    engine: Engine, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Differential test: force ``mimetypes.guess_extension`` to answer ``.hta`` for EVERY type and show
    the served filename is unmoved.

    This is the assertion that separates the shipped code from the code it replaced. An expectation
    written only as an output value would have passed on the old endpoint for most inputs, because the
    host registry usually agrees with the intent. Under this patch the old endpoint would have served
    ``attachment-<ref>.hta`` for both cases below."""
    monkeypatch.setattr(mimetypes, "guess_extension", lambda *a, **k: ".hta")

    # An allow-listed type keeps the allow-list's own extension.
    mid, ref = await _seed_labelled(engine, "application/pdf", marker="mt-pdf", prefix=b"%PDF-")
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == _disposition(ref, ".pdf")

    # A refused type keeps the allow-list's default extension.
    mid2, ref2 = await _seed_labelled(engine, "application/hta", marker="mt-hta")
    r2 = await client.get(f"/messages/{mid2}/attachments/{ref2}")
    assert r2.status_code == 200
    assert r2.headers["content-disposition"] == _disposition(ref2, _OCTET_EXT)


async def test_unrecognized_type_still_downloads(engine: Engine, client: httpx.AsyncClient) -> None:
    """The allow-list decides what is DECLARED, never whether the file is served.

    An inert-but-unlisted type (``audio/wav``) and an executable one (``application/hta``) take the same
    path: 200, bytes byte-for-byte, generic type, ``.bin`` name. Nothing about the route's availability
    or the count-and-log invariant moves — a stricter classifier that started refusing downloads would
    fail here."""
    for label, marker in (("audio/wav", "unlisted-audio"), ("application/hta", "unlisted-hta")):
        mid, ref = await _seed_labelled(engine, label, marker=marker)
        r = await client.get(f"/messages/{mid}/attachments/{ref}")
        assert r.status_code == 200
        assert r.content == f"synthetic document {marker} not real PHI".encode()
        assert _base_media_type(r) == _OCTET
        assert r.headers["content-disposition"] == _disposition(ref, _OCTET_EXT)


def test_pdf_stays_on_the_allowlist_by_recorded_decision() -> None:
    """``application/pdf`` is allow-listed on purpose, and the reasoning lives beside the table.

    PDF is the one entry that is not inert: a PDF may carry ``/JavaScript`` that runs when a saved file
    is opened in a viewer. It stays because the header this control sets governs rendering in the
    APPLICATION ORIGIN, and viewer script does not run there; because the declared type stops governing
    once the file is on disk, where the operator's own extension and file association take over; and
    because the instrument for the local-open threat is content scanning, which this route does not do.

    This test pins the decision so a later lane removing PDF has to confront the argument rather than
    silently reverse it. What it does NOT assert is anything about browser behaviour: no browser has been
    exercised by anyone, and the inline-rendering claim for ``Content-Disposition: attachment`` rests on
    specification alone."""
    assert _INERT_ATTACHMENT_TYPES["application/pdf"] == ".pdf"
    doc = _safe_attachment_content_type.__doc__ or ""
    assert "never whether the file is served" in doc


async def test_download_carries_sandbox_csp(engine: Engine, client: httpx.AsyncClient) -> None:
    """Every attachment download response carries ``default-src 'none'; sandbox`` — the clause the
    assessor scored as "no CSP on that response". ``sandbox`` with no ``allow-*`` token puts the
    response in a unique opaque origin, so nothing it contains can execute in the application origin."""
    mid, ref = await _seed_streaming(engine)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    expected = "default-src 'none'; sandbox; frame-ancestors 'none'"
    assert r.headers["content-security-policy"] == expected
    assert expected == _ATTACHMENT_CSP  # the constant the product actually ships
    # ASVS 3.4.6: `frame-ancestors` takes no fallback from `default-src`, so this policy NAMES it.
    # Asserting the served value is ONE field is the point -- the header floor appends a second
    # policy only where none names the directive, so this response stays governed by its own
    # constant and would still deny framing if the floor were removed or re-ordered.
    assert r.headers.get_list("content-security-policy") == [_ATTACHMENT_CSP]
    # The pre-existing layers are unchanged — the CSP is the fourth, not a replacement.
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("loopback", [False, True])
async def test_ui_delegate_serves_the_sandbox_csp_not_the_console_csp(
    engine: Engine, loopback: bool
) -> None:
    """THE ORDERING GUARD. The console's ``GET /ui/messages/{id}/attachments/{id}`` re-serves the very
    same ``Response`` object, but two ``/ui``-scoped middlewares ASSIGN a ``Content-Security-Policy`` on
    any non-static ``/ui`` path — the engine's ``ui_csp`` overlay and (on a secure context, which
    ``loopback=True`` engages per ADR 0143) the console's per-response nonce CSP. Neither contains
    ``sandbox``, so a route-level header alone is silently overwritten here.

    Mechanically asserts the SERVED header on the delegate is exactly the attachment CSP — the assertion
    fails the moment a middleware re-ordering puts a /ui CSP writer back on top."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    mid, ref = await _seed_streaming(engine)
    app = create_app(engine, auth=service, serve_ui=True, loopback=loopback)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (
            await c.post("/ui/login", data={"username": "op", "password": PW})
        ).status_code == 303
        r = await c.get(f"/ui/messages/{mid}/attachments/{ref}")
        assert r.status_code == 200
        assert r.content == DOC
        assert r.headers["content-security-policy"] == _ATTACHMENT_CSP
        assert "sandbox" in r.headers["content-security-policy"]
        # Proof the guard is not vacuous: a sibling /ui page on the SAME app does get a console CSP,
        # so the assertion above is discriminating between two live writers, not observing a no-op.
        # Under loopback the writer is the console's per-response nonce CSP (ADR 0143), the OUTERMOST
        # of the two — pinning the nonce proves the outer writer really is engaged on this app.
        page = await c.get("/ui/messages")
        assert page.status_code == 200
        assert "sandbox" not in page.headers["content-security-policy"]
        assert ("nonce-" in page.headers["content-security-policy"]) is loopback


async def test_download_unknown_message_is_404(client: httpx.AsyncClient) -> None:
    absent = "0" * 32  # a well-formed message id nothing seeded
    assert (await client.get(f"/messages/{absent}/attachments/" + "a" * 64)).status_code == 404
    # A message id that could not be one, and an attachment id that is not a 64-hex digest, are each
    # refused before the lookup (BACKLOG #1108). Paired with the 404 above so neither arm can pass by
    # the route simply refusing everything.
    assert (await client.get("/messages/missing/attachments/" + "a" * 64)).status_code == 422
    assert (await client.get(f"/messages/{absent}/attachments/nope")).status_code == 422


async def test_download_unlinked_attachment_is_404(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    # The SECURITY CRUX: an attachment that physically EXISTS but is NOT linked to this message must
    # never be pullable by guessing its content address (content-addressing shares a blob across
    # messages/tenants — the linkage is what scopes access).
    other_ref = await engine.store.put_attachment([DOC_B64], "application/pdf")
    mid = await engine.store.enqueue_message(channel_id="ch1", raw=ADT, deliveries=[])
    r = await client.get(f"/messages/{mid}/attachments/{other_ref}")
    assert r.status_code == 404


# --- RBAC + channel scope ----------------------------------------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    uid = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return uid


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def test_download_requires_view_raw(engine: Engine) -> None:
    # A detached document IS the raw body's PHI — same MESSAGES_VIEW_RAW gate as get_message. A Viewer
    # (no view_raw) is refused 403; an Operator (holds it) downloads it.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "vw", Role.VIEWER)
    mid, ref = await _seed_streaming(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        op = await _login(c, "op")
        vw = await _login(c, "vw")
        assert (await c.get(f"/messages/{mid}/attachments/{ref}", headers=op)).status_code == 200
        assert (await c.get(f"/messages/{mid}/attachments/{ref}", headers=vw)).status_code == 403


async def test_download_out_of_scope_message_is_404_not_403(engine: Engine) -> None:
    # A channel-scoped operator downloading an attachment on a message OUTSIDE their scope gets 404
    # (existence hidden), not 403 — mirroring get_message; the denial is audited.
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(uid, ["IB_A"], actor="admin")
    mid_a, ref_a = await _seed_streaming(engine, channel_id="IB_A")
    mid_b, ref_b = await _seed_streaming(engine, channel_id="IB_B")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        assert (await c.get(f"/messages/{mid_a}/attachments/{ref_a}", headers=h)).status_code == 200
        assert (await c.get(f"/messages/{mid_b}/attachments/{ref_b}", headers=h)).status_code == 404
    assert any(a["action"] == "auth.channel_denied" for a in await engine.store.list_audit())


# --- ASVS 1.3.4: the SVG served copy is sanitized, the stored value is not (BACKLOG #2299) ----------

#: A synthetic hostile SVG: a script, an event handler, a foreignObject, a javascript: link and an
#: external reference, around one harmless shape that must survive.
_HOSTILE_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    b'onload="alert(1)"><script>alert(2)</script>'
    b'<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>'
    b'<a xlink:href="javascript:alert(3)"><circle r="1"/></a>'
    b'<use xlink:href="http://evil.example/x.svg#a"/>'
    b'<rect id="kept" width="5" height="5" fill="#123456"/></svg>'
)


async def _stored_value(engine: Engine, ref: str) -> str:
    """The attachment's stored (verbatim base64) value, read straight from the store."""
    return "".join([chunk async for chunk in engine.store.read_attachment(ref)])


@pytest.mark.parametrize("label", ["image/svg+xml", "text/xml"])
async def test_svg_served_copy_is_sanitized_and_stored_value_is_untouched(
    engine: Engine, client: httpx.AsyncClient, label: str
) -> None:
    """``text/xml`` is here because the sanitizer keys on the document's root as well as the label, so
    a sender cannot skip it by mislabelling the SVG."""
    mid, ref = await _seed_labelled(
        engine, label, marker=label, prefix=_HOSTILE_SVG + b"<!--", suffix=b"-->"
    )
    before = await _stored_value(engine, ref)
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    served = r.content.lower()
    for needle in (
        b"script",
        b"onload",
        b"foreignobject",
        b"javascript",
        b"evil.example",
        b"alert",
    ):
        assert needle not in served, needle
    assert b'<rect id="kept" width="5" height="5" fill="#123456">' in r.content
    # The declared type and the download name are unchanged by the sanitizer.
    assert _base_media_type(r) == _OCTET
    assert r.headers["content-disposition"] == _disposition(ref, _OCTET_EXT)
    assert r.headers["content-security-policy"] == _ATTACHMENT_CSP
    # ADR 0105 owner ruling 3: the STORED value is byte-identical after the download.
    after = await _stored_value(engine, ref)
    assert after == before
    assert base64.b64decode(after).startswith(_HOSTILE_SVG)
    # The audit row says the served bytes were a sanitized copy, not the stored document.
    (row,) = [a for a in await engine.store.list_audit() if a["action"] == "attachment_download"]
    assert '"served": "sanitized-svg"' in (row["detail"] or "")


@pytest.mark.parametrize(
    ("label", "prefix", "suffix"),
    [
        ("image/svg+xml", b"<svg><rect>", b"</svg>"),
        (
            "image/svg+xml",
            b'<!DOCTYPE svg [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><svg>',
            b"&b;</svg>",
        ),
        (
            "text/xml",
            b'<!DOCTYPE d [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg">',
            b"</svg>",
        ),
    ],
    ids=["malformed", "entity-bomb", "entity-with-a-non-svg-label"],
)
async def test_svg_that_cannot_be_sanitized_is_refused_and_not_audited_as_served(
    engine: Engine,
    client: httpx.AsyncClient,
    caplog: pytest.LogCaptureFixture,
    label: str,
    prefix: bytes,
    suffix: bytes,
) -> None:
    """Fail closed: no copy of an SVG the parser cannot vet leaves the route, not even the original.
    The attempt is still audited, as a refusal and never as a download (BACKLOG #2387)."""
    mid, ref = await _seed_labelled(engine, label, marker=label, prefix=prefix, suffix=suffix)
    before = await _stored_value(engine, ref)
    with caplog.at_level(logging.WARNING):
        r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 422
    assert b"synthetic document" not in r.content
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "attachment download refused: svg_unsanitizable" in logged
    assert "synthetic document" not in logged
    await _assert_one_refusal_row(engine, mid, ref, "svg_unsanitizable")
    assert await _stored_value(engine, ref) == before


async def _assert_one_refusal_row(engine: Engine, mid: str, ref: str, reason: str) -> None:
    """Exactly one ``attachment_download_refused`` row whose detail is the id pair and ``reason`` and
    nothing else, so no byte of the document; no ``attachment_download`` row; no 'viewed' event."""
    audit = await engine.store.list_audit()
    assert not [a for a in audit if a["action"] == "attachment_download"]
    (row,) = [a for a in audit if a["action"] == "attachment_download_refused"]
    assert row["actor"]
    assert row["client"]
    assert row["channel_id"] == "ch1"
    assert json.loads(row["detail"]) == {"message_id": mid, "attachment_id": ref, "reason": reason}
    assert not any(e["event"] == "viewed" for e in await engine.store.events_for(mid))


async def test_undecodable_stored_value_is_refused_and_audited_as_a_refusal(
    engine: Engine, client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    """The route's other 422, a stored value that is not clean base64, gets the same refusal row."""
    # No whitespace in the marker: the route strips whitespace before decoding, so a spaced marker
    # would miss a leak of the normalized value.
    ref = await engine.store.put_attachment(["%%synthetic-undecodable-marker%%"], "application/pdf")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    with caplog.at_level(logging.WARNING):
        r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 422
    assert b"synthetic-undecodable-marker" not in r.content
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "attachment download refused: undecodable" in logged
    assert "undecodable-marker" not in logged
    await _assert_one_refusal_row(engine, mid, ref, "undecodable")


_SVG_PLANTED = "SYNTHETICPLANTEDSVG"


async def _get_with_a_failing_refusal_audit(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, mid: str, ref: str
) -> tuple[httpx.Response, BaseException]:
    """GET the attachment while the refusal row's write raises; the response and that error."""
    real = engine.store.record_audit
    raised: list[BaseException] = []

    async def failing(action: str, **kwargs: Any) -> Any:
        if action == "attachment_download_refused":
            exc = RuntimeError(
                f"synthetic audit store fault: {json.loads(kwargs['detail'])['reason']}"
            )
            raised.append(exc)
            raise exc
        return await real(action, **kwargs)

    monkeypatch.setattr(engine.store, "record_audit", failing)
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True), raise_app_exceptions=False
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/messages/{mid}/attachments/{ref}")
    (exc,) = raised
    return r, exc


@pytest.mark.parametrize(
    "prefix",
    [
        f'<!DOCTYPE svg [<!ENTITY {_SVG_PLANTED} "x">]><svg>'.encode(),
        f'<!DOCTYPE svg [<!ENTITY e SYSTEM "http://{_SVG_PLANTED}/">]><svg>&e;'.encode(),
        f'<?xml version="1.0" encoding="x-{_SVG_PLANTED}"?><svg>'.encode(),
    ],
    ids=["entity-name", "system-id", "encoding-label"],
)
async def test_a_failed_refusal_audit_carries_no_svg_text_onto_the_chain(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, prefix: bytes
) -> None:
    """A store fault on the refusal row turns the 422 into a 500, and nothing sender-controlled rides
    along (BACKLOG #2387, #1796). The parser's error can quote an entity name, a system id or an
    encoding label. If the audit write ran inside the ``except``, its error would chain that text,
    and a server such as uvicorn logs the whole chained traceback. ``format_exception`` stands in
    for that log, since the in-process transport does not run the server's logger."""
    mid, ref = await _seed_labelled(
        engine, "image/svg+xml", marker="failed-audit", prefix=prefix, suffix=b"</svg>"
    )
    r, exc = await _get_with_a_failing_refusal_audit(engine, monkeypatch, mid, ref)
    assert r.status_code == 500
    assert _SVG_PLANTED.encode() not in r.content
    # The ASGI stack's task groups may chain an ExceptionGroup on the way out; the parser's error
    # must not be anywhere on it. format_exception also walks the groups' members.
    chain = _chain(exc)
    assert str(exc).endswith("svg_unsanitizable")
    fields = [
        (str(e), repr(e.args), repr(vars(e)), repr(getattr(e, "object", None))) for e in chain
    ]
    assert not [e for e in chain if isinstance(e, SvgRejected)], chain
    assert not [f for f in fields if any(_SVG_PLANTED in x for x in f)]
    assert _SVG_PLANTED not in "".join(traceback.format_exception(exc, chain=True))


async def test_a_failed_undecodable_refusal_audit_chains_no_decode_error(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other 422 keeps the same order: its decode error is never on a failed audit's chain."""
    ref = await engine.store.put_attachment(["%%synthetic-undecodable-fault%%"], "application/pdf")
    mid = await engine.store.enqueue_ingress(channel_id="ch1", raw=ADT, attachment_refs=[ref])
    r, exc = await _get_with_a_failing_refusal_audit(engine, monkeypatch, mid, ref)
    assert r.status_code == 500
    assert str(exc).endswith("undecodable")
    assert not [e for e in _chain(exc) if isinstance(e, (binascii.Error, ValueError))]


def test_the_chain_walker_finds_a_parser_error_raised_inside_the_handler() -> None:
    """Control for the test above: the shape it replaced is found, so a clean reading means clean."""
    try:
        try:
            raise SvgRejected("refused") from ValueError(_SVG_PLANTED)
        except SvgRejected:
            raise RuntimeError("synthetic audit store fault")  # noqa: B904 - the shape under test
    except RuntimeError as exc:
        found = exc
    assert len(_chain(found)) == 3
    assert _SVG_PLANTED in "".join(traceback.format_exception(found, chain=True))


def _chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` by ``__cause__`` or ``__context__``, ``exc`` first."""
    seen: list[BaseException] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or any(cur is s for s in seen):
            continue
        seen.append(cur)
        stack += [cur.__cause__, cur.__context__]
    return seen


async def test_svg_label_on_non_markup_bytes_is_served_unchanged(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """No SVG reader renders bytes that do not start with ``<``, so an SVG label alone changes nothing:
    the document is served byte for byte under the generic type, and the audit row claims no copy."""
    mid, ref = await _seed_labelled(engine, "image/svg+xml", marker="svg-label-on-text")
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.content == b"synthetic document svg-label-on-text not real PHI"
    assert _base_media_type(r) == _OCTET
    (row,) = [a for a in await engine.store.list_audit() if a["action"] == "attachment_download"]
    assert "sanitized-svg" not in (row["detail"] or "")


async def test_non_svg_xml_is_served_byte_for_byte(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """An XML document whose root is not ``svg`` is not the sanitizer's business, even if it embeds one."""
    prefix, suffix = (
        b'<?xml version="1.0"?><ClinicalDocument><svg onload="x"/><note>',
        b"</note></ClinicalDocument>",
    )
    mid, ref = await _seed_labelled(
        engine, "application/xml", marker="cda", prefix=prefix, suffix=suffix
    )
    r = await client.get(f"/messages/{mid}/attachments/{ref}")
    assert r.status_code == 200
    assert r.content == prefix + b"synthetic document cda not real PHI" + suffix


# NOTE: test_runbook_documents_the_shipped_download_safety_mechanism moved to tests/test_off_loopback_runbook.py (2026-07-26). They asserted against
# the deny-listed off-loopback runbook, so on the public mirror they failed at runtime and took
# this whole module's required test leg red — while the rest of this file guards shipped
# behaviour that must keep running publicly. The new home already carries the doc-absent guard.
