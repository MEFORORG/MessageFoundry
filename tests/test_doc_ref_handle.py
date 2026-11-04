# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Live document-handle helpers (#149, ADR 0105 Phase 0). A very-large document detached from a message
is replaced in place by a small ``mfdoc:v1:ref:<sha256>:<content-type>`` handle — a LIVE sibling of the
``mfdoc:v1:pruned:`` tombstone (#47), unified with #94's opaque-pointer contract. These helpers are pure
and carry the exact bytes (Approach B is verbatim — no decode/encode); this pins the round-trip + the
three-way discrimination (ref vs pruned-tombstone vs plain value). Mirrors ``test_binary_carriage.py`` /
``test_embedded_document_pruning.py``.
"""

from __future__ import annotations

import hashlib

import pytest

from messagefoundry.parsing.binary import (
    DOC_REF_MARKER,
    DocRefError,
    _copy_names_address,
    is_doc_ref,
    is_document_tombstone,
    is_marked,
    make_doc_ref,
    make_document_tombstone,
    parse_doc_ref,
)
from messagefoundry.parsing.message import Message

SHA = hashlib.sha256(b"a base64 pdf the partner sent, verbatim").hexdigest()


def test_doc_ref_roundtrip_and_discrimination() -> None:
    handle = make_doc_ref(SHA, "application/pdf")
    assert handle == f"{DOC_REF_MARKER}{SHA}:application/pdf"
    assert is_doc_ref(handle)
    assert parse_doc_ref(handle) == (SHA, "application/pdf")

    # A ref is NOT a pruned tombstone and NOT a whole-body mfb64 carriage value, and vice-versa — the
    # three markers are cleanly distinguished so a reader never confuses a LIVE handle for a DEAD one.
    tombstone = make_document_tombstone(1234, "application/pdf", pruned_at=0.0)
    assert is_document_tombstone(tombstone)
    assert not is_doc_ref(tombstone)  # pruned: discriminator differs from ref:
    assert not is_document_tombstone(handle)
    assert not is_marked(handle)  # mfdoc:v1:ref: is not the mfb64:v1: carriage marker
    assert not is_doc_ref("MSH|^~\\&|A|B")  # a plain value is neither


def test_make_doc_ref_rejects_bad_content_address() -> None:
    with pytest.raises(DocRefError):
        make_doc_ref("not-a-sha", "application/pdf")
    with pytest.raises(DocRefError):
        make_doc_ref(SHA[:-1], "application/pdf")  # 63 hex — wrong length
    with pytest.raises(DocRefError):
        make_doc_ref(SHA[:-1] + "z", "application/pdf")  # non-hex char


def test_make_doc_ref_accepts_upper_hex_and_normalizes() -> None:
    # A caller may hand an upper-case digest; the handle normalizes it so the content address is stable.
    handle = make_doc_ref(SHA.upper(), "application/pdf")
    assert parse_doc_ref(handle) == (SHA, "application/pdf")


def test_make_doc_ref_sanitizes_structural_chars_in_content_type() -> None:
    # A content-type carrying ``:`` or HL7 delimiters would re-split the field / corrupt the handle;
    # make_doc_ref sanitizes them (mirrors make_document_tombstone), so parse stays unambiguous.
    handle = make_doc_ref(SHA, "weird:type|with^delims")
    sha, ct = parse_doc_ref(handle)
    assert sha == SHA
    assert ":" not in ct and "|" not in ct and "^" not in ct
    assert ct == "weird_type_with_delims"


def test_make_doc_ref_defaults_blank_content_type() -> None:
    handle = make_doc_ref(SHA, "")
    _, ct = parse_doc_ref(handle)
    assert ct == "application/octet-stream"


def test_parse_doc_ref_rejects_non_ref_and_malformed() -> None:
    with pytest.raises(DocRefError):
        parse_doc_ref("MSH|^~\\&|A|B")  # missing marker
    with pytest.raises(DocRefError):
        parse_doc_ref(make_document_tombstone(1, "x", 0.0))  # a tombstone is not a ref
    with pytest.raises(DocRefError):
        parse_doc_ref(f"{DOC_REF_MARKER}{SHA}")  # missing content-type
    with pytest.raises(DocRefError):
        parse_doc_ref(f"{DOC_REF_MARKER}deadbeef:application/pdf")  # content address not 64-hex


def test_copy_names_address_needs_64_lowercase_hex_right_after_the_marker() -> None:
    # The scan delivery uses to tell a handle copy from a bare marker (BACKLOG #5099): the marker,
    # at any occurrence, immediately followed by 64 lowercase hex characters.
    assert _copy_names_address(f"x {DOC_REF_MARKER}{SHA} y", DOC_REF_MARKER)
    assert _copy_names_address(f"{DOC_REF_MARKER}{SHA}0", DOC_REF_MARKER)  # no terminator needed
    assert not _copy_names_address(f"{DOC_REF_MARKER}{SHA[:63]}", DOC_REF_MARKER)
    assert not _copy_names_address(f"{DOC_REF_MARKER}{SHA[:63]}:x", DOC_REF_MARKER)
    assert not _copy_names_address(f"{DOC_REF_MARKER}{SHA.upper()}", DOC_REF_MARKER)
    assert not _copy_names_address(f"a {SHA} b", DOC_REF_MARKER)  # marker absent
    assert not _copy_names_address(f"{DOC_REF_MARKER} {SHA}", DOC_REF_MARKER)
    # A first hit naming no address does not hide a later one that does.
    assert _copy_names_address(
        f"{DOC_REF_MARKER}nothing then {DOC_REF_MARKER}{SHA}", DOC_REF_MARKER
    )
    # Overlapping hits are each checked: in "a:a:a<sha>" the marker "a:a" starts at 0, followed by
    # ":a", and again at 2, followed by the address. A scan resuming past the first hit misses it.
    assert _copy_names_address(f"a:a:a{SHA}", "a:a")
    # The marker as a payload's delimiters escape it, which is what delivery passes: under a ":"
    # component separator the copy carries the escaped marker. A raw marker beside it naming no
    # address is not a copy, so only the escaped search finds one.
    escaped = Message._escape_leaf(DOC_REF_MARKER, "|", ":", "~", "\\", "&")
    assert escaped != DOC_REF_MARKER
    body = f"NTE|1||{DOC_REF_MARKER}x|{escaped}{SHA}\\S\\application/pdf"
    assert _copy_names_address(body, escaped)
    assert not _copy_names_address(body, DOC_REF_MARKER)
