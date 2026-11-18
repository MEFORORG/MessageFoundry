# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The hardened lxml parser — the single place an ``lxml.etree.XMLParser`` is constructed for the XML
codec, locked down against XML attacks on **untrusted** inbound bodies (BACKLOG #31).

``defusedxml`` does **not** cover ``lxml`` (it patches the stdlib ``xml.*`` modules), and
``defusedxml.lxml`` is deprecated, so we harden the lxml parser **directly** here. Every parse in the
codec goes through :func:`hardened_parser`, so the lockdown can't be bypassed by a caller reaching for
lxml's permissive defaults.

Guards (all on by design — inbound HL7/XML is attacker-influenceable, CLAUDE.md §8):

* ``resolve_entities=False`` — custom entity references are **not** expanded → blocks classic XXE and
  billion-laughs entity-expansion DoS at the source.
* ``no_network=True`` — the parser never opens a network connection (no external-DTD / external-entity
  fetch → no SSRF via a crafted ``SYSTEM`` URL).
* ``load_dtd=False`` / ``dtd_validation=False`` — no DTD is loaded or processed.
* ``huge_tree=False`` — keep libxml2's built-in limits on tree size/depth (another expansion-DoS bound).
* ``DOCTYPE`` rejection — :func:`parse_bytes` additionally **rejects any document carrying a DOCTYPE**
  (``etree.DOCSTRING``/``DTD`` in the tree), so a payload can't smuggle entity *definitions* even
  though references wouldn't be resolved — defense in depth, mirroring defusedxml's ``forbid_dtd``.
  A document that fails to parse is refused too, with a message of its own, when its prolog opens
  a DOCTYPE within the bytes and encodings :func:`_declares_doctype` reads.
* **No second decode** — for ``str`` input, :func:`parse_bytes` neutralizes the XML declaration's
  ``encoding=`` pseudo-attribute before encoding to UTF-8 (ASVS 1.5.3, see
  :func:`_without_declared_encoding`).
"""

from __future__ import annotations

import re
from typing import Any

from messagefoundry.parsing.xml._deps import load_lxml
from messagefoundry.parsing.xml.errors import XmlParseError, XmlSecurityError

#: The ``encoding="…"`` pseudo-attribute of an XML declaration at the very start of the text (a
#: leading BOM character is tolerated, since a ``str`` decoded from a BOM-prefixed body keeps it).
#:
#: Linear because of the ``(?<!\s)``, not because it is anchored (BACKLOG #2561). Without it the lazy
#: head could stop anywhere inside a whitespace run, and ``\s+`` re-walked the rest of the run from
#: each stop: quadratic, about 0.2 s for 16,000 spaces. Slicing at the first ``>`` would not help,
#: since the run sits inside the declaration. The lookbehind changes no match, because a stop inside a
#: run never wins over the run's start. ``tests/test_xml_declared_encoding_regex.py`` holds both.
_DECLARED_ENCODING = re.compile(
    r"\A(\ufeff?<\?xml\b[^>]*?)(?<!\s)\s+encoding\s*=\s*(\"[^\"]*\"|'[^']*')"
)


def hardened_parser() -> Any:
    """A freshly-constructed, locked-down ``lxml.etree.XMLParser``.

    A new parser per call avoids any cross-document state and is cheap. Requires the ``[xml]`` extra
    (raises :class:`RuntimeError` if absent)."""
    etree = load_lxml()
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        # Strip nothing implicitly; collapse no whitespace — preserve the document faithfully.
        remove_blank_text=False,
    )


def _without_declared_encoding(text: str) -> str:
    """Drop an XML declaration's ``encoding=`` pseudo-attribute (ASVS 1.5.3 parser agreement).

    A ``str`` reaching the codec was already decoded **exactly once**, by the connection, using the
    connection's own declared encoding (ASVS 1.1.1) — so its characters are settled and the document's
    own ``encoding=`` claim is stale metadata about bytes nobody will look at again. Encoding that str
    to UTF-8 and leaving the claim in place tells libxml2 to decode those UTF-8 bytes as, say,
    ISO-8859-1: a **second** decode, and the one the ingress invariant exists to prevent.

    Left in place, that is parser confusion between two surfaces reading the *same*
    ``RawMessage.raw``: ``rm.xml()`` (defusedxml, which ignores the declaration for ``str`` input)
    returns ``José`` where ``XmlMessage.parse(rm.raw)`` returns ``JosÃ©`` — both **accepting**, and
    disagreeing about a PHI value. Dropping the claim makes the two read the str's own characters, and
    is only ever a no-op for a body whose declaration already matched.

    Only the declaration is touched; nothing else in the document moves. Bytes input is untouched —
    there the declaration is the sender's genuine, first-and-only statement about its own bytes.
    """
    return _DECLARED_ENCODING.sub(r"\1", text, count=1)


_DOCTYPE_REFUSAL = (
    "refusing an XML document that declares a DOCTYPE/DTD (entity-definition carrier)"
)

#: The failed-parse arm's own text. Such a document opens a DOCTYPE in its prolog and the parser
#: did not finish it: it may be malformed, or well-formed and stopped by a parser limit, as an
#: entity-expansion bomb is. An unfinished parse reports nothing about what the DOCTYPE holds, so
#: the text names the DOCTYPE and the failed parse, and no entity.
_BROKEN_DOCTYPE_REFUSAL = (
    "refusing an XML document that opens a DOCTYPE in its prolog and that the parser did not finish"
)

#: Encodings a failed document is read in to look for a DOCTYPE. ``latin-1`` stands for every
#: ASCII-compatible encoding, UTF-8 included; the others are some of the wide encodings libxml2
#: detects. Not every encoding libxml2 reads is here (at least EBCDIC, UCS-4 2143/3412 and a declared
#: UTF-7 are not), so a DOCTYPE written in one of those that fails to parse is a parse error.
_DOCTYPE_SCAN_CODECS = ("latin-1", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")

#: How many leading bytes of a failed document the DOCTYPE scan reads (a multiple of 4, so no wide
#: codec splits a code unit). A failure then costs one bounded pass per codec whatever the body's
#: size. A DOCTYPE behind a longer prolog is reported as a parse error, which still refuses it.
_DOCTYPE_SCAN_BYTES = 64 * 1024

#: A DOCTYPE in the prolog: at most one byte-order mark (U+FEFF, or the UTF-8 BOM as latin-1 reads
#: it), then only XML whitespace (the S production, not Unicode's), processing instructions (the
#: XML declaration among them) and comments. The atomic groups and the possessive loop keep it
#: linear.
_PROLOG_DOCTYPE = re.compile(
    # (?-i:...): IGNORECASE would fold \xef to \xcf and take CF BB BF for a BOM.
    r"\A(?-i:\N{BYTE ORDER MARK}|\xef\xbb\xbf)?"
    r"(?:[ \t\r\n]|<\?(?>.*?\?>)|<!--(?>.*?-->))*+<!DOCTYPE",
    re.IGNORECASE | re.DOTALL,
)


def _declares_doctype(payload: bytes) -> bool:
    """Whether ``payload``'s prolog opens a ``<!DOCTYPE``, in any case, read in each scan codec.

    Only called on a document that already failed to parse, and reads only its first
    ``_DOCTYPE_SCAN_BYTES``. Anchored to the prolog, so a mention in an element's content, an
    attribute, a comment after the root or a CDATA section is not one."""
    head = payload[:_DOCTYPE_SCAN_BYTES]
    return any(
        _PROLOG_DOCTYPE.match(head.decode(codec, "ignore")) is not None
        for codec in _DOCTYPE_SCAN_CODECS
    )


def parse_bytes(data: bytes | str) -> Any:
    """Parse ``data`` into an lxml element tree with the hardened parser, refusing any DOCTYPE.

    Returns the root ``_Element``. Raises :class:`XmlSecurityError` if the document declares a DOCTYPE
    (a DTD/entity-definition carrier), and, with a message of its own, when the document fails to
    parse but its prolog opens a DOCTYPE within its first 64 KiB (``_DOCTYPE_SCAN_BYTES``), read as
    latin-1 (which stands for every ASCII-compatible encoding, UTF-8 included) or as UTF-16 or
    UTF-32 in either byte order (``_DOCTYPE_SCAN_CODECS``, whose comment names encodings the scan
    does not read); and :class:`XmlParseError` if it is not well-formed XML. Each
    message is fixed text plus, for a parse error, the fault's line, column and libxml2 error code;
    none carries lxml's message, and none is chained from lxml's error (BACKLOG #5371). Requires
    the ``[xml]`` extra."""
    etree = load_lxml()
    if isinstance(data, str):
        payload: bytes = _without_declared_encoding(data).encode("utf-8")
    else:
        payload = bytes(data)
    parser = hardened_parser()
    fault: str | None = None
    try:
        root = etree.fromstring(payload, parser=parser)
    except etree.XMLSyntaxError as exc:
        # lxml's message can quote element and entity names and the bytes at the fault, so keep only
        # the position and libxml2's numeric code (BACKLOG #5371).
        line, column = exc.position
        fault = f"line {line}, column {column} (libxml2 error {exc.code})"
    if fault is not None:
        # Raised outside the handler so lxml's error is on neither __cause__ nor __context__.
        if _declares_doctype(payload):
            # A failed parse whose prolog opens a DOCTYPE that _declares_doctype finds, within its
            # scan limits, is refused, not reported as a typo. At least a DOCTYPE cut short and a
            # complete one with the fault after it both take this arm.
            raise XmlSecurityError(_BROKEN_DOCTYPE_REFUSAL)
        raise XmlParseError(f"not well-formed XML at {fault}")
    # Defense in depth: refuse any DOCTYPE so entity *definitions* can't ride along (references are
    # already not resolved). getroottree().docinfo exposes the parsed DOCTYPE, if any.
    docinfo = root.getroottree().docinfo
    if docinfo is not None and (docinfo.doctype or docinfo.internalDTD or docinfo.externalDTD):
        raise XmlSecurityError(_DOCTYPE_REFUSAL)
    return root
