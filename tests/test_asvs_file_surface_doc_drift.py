# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 5.1.1 — file-surface doc-drift guard for `docs/CONNECTIONS.md`.

The old `#### File handling & quarantine policy (ASVS 5.1.1)` intro carried a factually false denial —
"the directory source is the only file-ingest path — there is no HTTP file upload/download endpoint" —
even though the engine ships the opt-in HTTP **uploaded-logs upload** (POST `/uploads` + the
`/ui/uploaded-logs/upload` delegate, ADR 0134) and the **attachment download** route (GET
`/messages/{message_id}/attachments/{attachment_id}`, ADR 0105). These tripwires pin the corrected file
surface and the shipped hardening so the doc cannot silently revert to the false claim or drift off the
controls 5.2.2 / 5.2.4 / 14.2.8 / 1.3.4 actually ship.

Doc-text only (no store, no I/O beyond reading the shipped doc files) — the 1.3.4 download mechanism it
pins is #284's code, which the doc describes ahead of the merge, so this guards TEXT not code.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_CONNECTIONS = (_REPO / "docs" / "CONNECTIONS.md").read_text(encoding="utf-8")
_CONFIGURATION = (_REPO / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")


def _uploaded_logs_block() -> str:
    """The `#### Uploaded-logs file policy (ASVS 5.1.1)` block, sliced up to the next `###`/`####`
    heading, so token assertions can't false-positive on unrelated prose elsewhere in the file."""
    marker = "#### Uploaded-logs file policy (ASVS 5.1.1)"
    start = _CONNECTIONS.index(marker)
    rest = _CONNECTIONS[start + len(marker) :]
    # end at the next markdown heading of level <= 4 (the ### REST section, or any #### sibling).
    ends = [rest.index(h) for h in ("\n### ", "\n#### ") if h in rest]
    stop = min(ends) if ends else len(rest)
    return rest[:stop]


def test_false_no_http_endpoint_denial_is_gone() -> None:
    """The struck factually-false sentence must not reappear anywhere in CONNECTIONS.md."""
    assert "no HTTP file upload/download endpoint" not in _CONNECTIONS
    assert "the only file-ingest path" not in _CONNECTIONS


def test_file_surface_names_upload_and_download_routes() -> None:
    """The corrected 5.1.1 file surface must name the HTTP upload route AND the attachment download
    route (both the ADR 0134 upload and the ADR 0105 download endpoints)."""
    assert "POST `/uploads`" in _CONNECTIONS
    assert "/ui/uploaded-logs/upload" in _CONNECTIONS
    # The route path is the load-bearing token; "GET" may wrap onto the previous line.
    assert "`/messages/{message_id}/attachments/{attachment_id}`" in _CONNECTIONS


def test_uploaded_logs_block_pins_shipped_upload_controls() -> None:
    """The uploaded-logs policy block must document ONLY the controls 5.2.2 / 5.2.4 / 14.2.8 ship:
    the extension allowlist, the 400 mismatch reject + `upload.reject` audit, the 415 non-text/container
    reject, the per-user quota/retention caps, and the no-decompression statement."""
    block = _uploaded_logs_block()
    # 5.2.2 — extension allowlist + content sniff, 400 + metadata-only audit.
    for ext in (".hl7", ".hl7v2", ".txt", ".xml"):
        assert ext in block
    assert "HTTP 400" in block
    assert "upload.reject" in block
    # 14.2.8 — text-only 415 on non-text/container bodies.
    assert "HTTP 415" in block
    # 5.2.4 — per-user quota + retention.
    assert "max_upload_files_per_user" in block
    assert "max_upload_total_bytes_per_user" in block
    assert "uploads_retention_days" in block
    assert "HTTP 409" in block
    # 5.2.3 — explicit no-decompression / uploads-are-never-unpacked statement.
    assert "never unpacked" in block
    assert "split_batch" in block


def test_uploaded_logs_block_does_not_claim_a_scanrejected_upload_seam() -> None:
    """BINDING (skeptic REVISE): the malicious-file sentence must be scoped to shipped controls — it must
    NOT claim a `ScanRejected` upload seam (that seam lives in the owner-blocked 5.4.3 fork and does not
    exist on the upload path). Any `ScanRejected` mention in the block must be the connector-path
    scoping statement, never an upload-path control."""
    block = _uploaded_logs_block()
    if "ScanRejected" in block:
        # It may appear ONLY to say the scan-hook seam does NOT apply to HTTP uploads.
        assert "applies only to the `File(...)`/remote directory sources" in block


def test_downloads_made_safe_mechanism_tokens_pinned() -> None:
    """The downloads-made-safe sentence must pin #284's shipped 1.3.4 mechanism tokens: octet-stream
    forcing (incl. the browser-active downgrade), Content-Disposition attachment, nosniff, and the
    sandbox CSP. This is the drift-guard anchor the brief names."""
    block = _uploaded_logs_block()
    assert "application/octet-stream" in block  # octet-stream forcing
    assert "_safe_attachment_content_type" in block  # the forcing function
    assert "browser-active" in block  # the html/xml/script/svg + multipart downgrade
    assert "Content-Disposition: attachment" in block
    assert "X-Content-Type-Options: nosniff" in block
    assert "default-src 'none'; sandbox" in block  # the sandbox CSP


def test_configuration_md_documents_upload_and_quota_keys() -> None:
    """CONFIGURATION.md `[store]` must carry the uploaded-logs storage + quota/retention keys so the
    5.2.4 defaults are discoverable and pinned."""
    for key in (
        "`uploads_dir`",
        "`max_upload_bytes`",
        "`max_upload_files_per_user`",
        "`max_upload_total_bytes_per_user`",
        "`uploads_retention_days`",
    ):
        assert key in _CONFIGURATION
