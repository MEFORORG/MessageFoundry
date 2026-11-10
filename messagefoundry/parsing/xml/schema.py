# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in XSD schema validation for the XML codec (``xmlschema`` behind the ``[xml]`` extra, BACKLOG
#31) — the XML analog of the X12 :func:`~messagefoundry.parsing.x12.validate.validate` strict tier.

A Handler calls :func:`validate_against` on demand against a local schema; **remote ``schemaLocation``
fetching is disabled** so a crafted document can't make the validator open a network connection (SSRF),
mirroring the no-network lockdown of :mod:`messagefoundry.parsing.xml.harden`. An inline schema opens
no file of its own, and a schema given as a path opens files only under its own directory; either may
read xmlschema's bundled copies of well-known namespaces (:func:`_build_schema` says how).

**PHI rule:** a validation failure is reported with the failing element *path* and *reason category*
only (xmlschema's structural reason), never the offending element value.

Pure: no engine imports; the only network the validator could do (schema fetch) is disabled.
"""

from __future__ import annotations

import codecs
import email.message
import functools
import io
import os
import urllib.request
import urllib.response
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from messagefoundry.parsing.xml._deps import load_lxml, load_xmlschema
from messagefoundry.parsing.xml.errors import XmlValidationError
from messagefoundry.parsing.xml.harden import parse_bytes

__all__ = ["XmlSchemaResult", "validate_against"]


@dataclass(frozen=True)
class XmlSchemaResult:
    """The outcome of an XSD validation pass. ``valid`` is True iff the document conforms; ``reasons``
    is a tuple of **PHI-safe** failure summaries (failing element *path* + reason category), empty when
    valid."""

    valid: bool
    reasons: tuple[str, ...] = ()


#: Byte-order marks a bytes schema document may open with. No filesystem path starts with one, so a
#: bytes source carrying one is the XSD itself (BACKLOG #5537).
_BOMS = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,  # BOM_UTF32_LE starts with BOM_UTF16_LE, so it needs no entry
    codecs.BOM_UTF32_BE,
)


def _is_inline_xml(schema_source: str | bytes) -> bool:
    """True when ``schema_source`` is the XSD **document** rather than a path/URL to one.

    A leading byte-order mark counts as document text. Without that, a BOM-prefixed schema was read as
    a path: a ``str`` failed to load, and a ``bytes`` one skipped the hardened pre-parse below, so
    xmlschema parsed the raw text itself and expanded a DOCTYPE entity (BACKLOG #5537)."""
    if isinstance(schema_source, (bytes, bytearray)):
        head = schema_source[:4]
        # A path never holds a NUL; UTF-16/32 text without a BOM opens with one beside its "<".
        return (
            schema_source.startswith(_BOMS)
            or schema_source.lstrip()[:1] == b"<"
            or (b"\x00" in head and b"<" in head)
        )
    return schema_source.removeprefix("\N{BYTE ORDER MARK}").lstrip()[:1] == "<"


def _within(path: str, root: str) -> bool:
    """Whether ``path`` is ``root`` or lies beneath it, compared as whole path components."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives, or one relative and one absolute
        return False


def _is_network_or_device(path: str) -> bool:
    """A UNC (two leading separators, then host and share) or Win32 device (``//./pipe/...``) path, in either separator.
    Resolving one opens it on Windows, which is a network or named-pipe connection."""
    return path.replace("\\", "/").startswith("//")


@dataclass(frozen=True)
class _Root:
    """A directory reads are confined to: as written (``lexical``) and with links resolved (``real``),
    both ``normcase``d for comparison only."""

    lexical: str
    real: str
    vet: bool  # whether each file read under it goes through parse_bytes first

    @classmethod
    def of(cls, directory: str, *, vet: bool) -> _Root:
        return cls(
            os.path.normcase(os.path.abspath(directory)),
            os.path.normcase(os.path.realpath(directory)),
            vet,
        )


@functools.cache
def _bundled_root(module_file: str) -> _Root:
    """xmlschema's own ``schemas`` directory, which holds its copies of well-known namespaces."""
    return _Root.of(os.path.join(os.path.dirname(module_file), "schemas"), vet=False)


class _ConfinedFiles(urllib.request.BaseHandler):
    """The only way xmlschema can open a resource here: ``file:`` URLs under fixed roots (BACKLOG #5537).

    Installed as xmlschema's ``opener``, so it sees every open xmlschema makes, the top-level schema
    and each include, import, redefine and override, with no ``http``/``ftp`` handler beside it. One
    root is xmlschema's bundled ``schemas`` directory, which holds the copies of well-known namespaces
    (SOAP encoding, XML-DSig, xlink and others) a location-free ``xs:import`` resolves to; those are
    library files and are read as they are. For a schema given as a path, the other root is its own
    directory, and each file under it is checked by
    :func:`~messagefoundry.parsing.xml.harden.parse_bytes` first, so a path schema and its includes meet
    the same DOCTYPE refusal as an inline one. Anything else raises xmlschema's own
    ``XMLResourceBlocked``: an include then fails the build, and an import is skipped with a warning.

    The location is judged on its text first, and resolved only once it is inside a root: on Windows
    ``realpath`` opens the path, so resolving a UNC or device location before refusing it would already
    have connected to it. Then the resolved path must be inside the same root, so a symlink does not get
    out. Paths are compared by whole components, so a sibling directory sharing a name prefix
    (``schemas-old`` beside ``schemas``) is outside."""

    def __init__(self, blocked: type[Exception], roots: tuple[_Root, ...]) -> None:
        self._blocked = blocked
        self._roots = roots

    def file_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        url = req.full_url
        parts = urlsplit(url)
        written = urllib.request.url2pathname(parts.path)
        if parts.netloc in ("", "localhost") and not _is_network_or_device(written):
            lexical = os.path.normcase(os.path.abspath(written))
            for root in self._roots:
                if not (_within(lexical, root.lexical) or _within(lexical, root.real)):
                    continue
                real = os.path.realpath(written)
                if not _within(os.path.normcase(real), root.real):
                    break  # a link out of the root
                with open(real, "rb") as fh:
                    data = fh.read()
                if root.vet:
                    parse_bytes(data)  # raises XmlSecurityError / XmlParseError; tree discarded
                return urllib.response.addinfourl(io.BytesIO(data), email.message.Message(), url)
        # PHI-safe: names no part of the location. xmlschema adds the URL to its own warning.
        raise self._blocked("block access to a resource outside the schema's own directory")


def _schema_file(schema_source: str | bytes) -> str:
    """The real, absolute file a non-inline ``schema_source`` names: a local filesystem path, or a
    ``file:`` URL with no host. A remote URL, another scheme, or a UNC or device path is refused."""
    source = os.fsdecode(schema_source).strip()
    parts = urlsplit(source)
    scheme = parts.scheme.lower()
    if scheme == "file":
        if parts.netloc not in ("", "localhost"):
            raise ValueError("a file URL naming a host")  # _build_schema reports the type only
        source = urllib.request.url2pathname(parts.path)
    elif scheme and not (len(scheme) == 1 and source[1:2] == ":"):  # a drive letter is not a scheme
        raise ValueError("a schema location that is not a local path")
    if _is_network_or_device(source):
        raise ValueError("a UNC or device path")
    return os.path.realpath(source)


def _build_schema(xmlschema_mod: Any, schema_source: str | bytes) -> Any:
    """Construct an ``xmlschema.XMLSchema`` that opens no file beyond the schema it was given.

    An **inline** schema is parsed by :func:`~messagefoundry.parsing.xml.harden.parse_bytes` first, so
    the XSD goes through the same lockdown as every other document and xmlschema is handed an
    already-hardened tree instead of raw text (ASVS 1.5.3). Without that it parsed the source with its
    own **non-defused** ElementTree: an XSD carrying
    ``<!DOCTYPE xs:schema [<!ENTITY nm "patient">]>`` was parsed and its internal entity **expanded**,
    while ``parse_bytes`` refuses a DOCTYPE outright. An inline schema's own include, import, redefine
    or override location is never opened, local or remote: an include or a redefine that needs one
    fails the build, and an import that needs one is skipped, so a type only it defines fails the build.

    A schema given as a **path** (or a host-less ``file:`` URL) opens itself and files under its own
    directory, each checked by ``parse_bytes``. A schema at a filesystem root is confined to itself,
    since its directory would be every file on that volume.

    Both rely on :class:`_ConfinedFiles` as xmlschema's opener, with ``allow="local"`` so xmlschema
    refuses a remote URL before it reaches the opener, and ``defuse="always"`` so its own entity check
    runs on every file as well. Before BACKLOG #5537 this was ``allow="local"`` with no opener and the
    default ``defuse="remote"``, and an inline schema's ``xs:include`` of a ``file:`` URL read that local
    file and expanded a DOCTYPE entity inside it. xmlschema's ``allow="sandbox"`` is not used: it
    compares URL string prefixes, and it narrows to each includer's own directory, so a nested include
    that climbs back inside the top-level directory was refused.
    """
    blocked = xmlschema_mod.exceptions.XMLResourceBlocked
    roots: tuple[_Root, ...] = (_bundled_root(xmlschema_mod.__file__),)
    try:
        if _is_inline_xml(schema_source):
            source: Any = parse_bytes(schema_source)
        else:
            source = _schema_file(schema_source)
            directory = os.path.dirname(source)
            # A filesystem root is its own parent; confine a schema there to itself.
            roots += (
                _Root.of(
                    source if os.path.dirname(directory) == directory else directory, vet=True
                ),
            )
        opener = urllib.request.OpenerDirector()
        opener.add_handler(_ConfinedFiles(blocked, roots))
        return xmlschema_mod.XMLSchema(source, allow="local", defuse="always", opener=opener)
    except Exception as exc:  # xmlschema (and now harden) raise their own hierarchies
        # The exception TYPE names which gate refused it (XmlSecurityError = the XSD carried a
        # DOCTYPE) without quoting the schema text. Keeps validate_against's documented contract:
        # a schema that cannot be loaded is always XmlValidationError.
        raise XmlValidationError(f"could not load XSD schema: {type(exc).__name__}") from exc


def validate_against(document: str | bytes, schema_source: str | bytes) -> XmlSchemaResult:
    """Validate ``document`` against the XSD ``schema_source`` (a schema string/bytes or a local path).

    Returns an :class:`XmlSchemaResult`; a well-formed document that does not conform is returned as
    data, never raised, so a Handler can route the message and still see why. Raises
    :class:`~messagefoundry.parsing.xml.errors.XmlValidationError` when the schema itself can't be
    loaded, and :class:`RuntimeError` if the ``[xml]`` extra is absent. A ``document`` the hardened
    parser refuses is raised, not returned: :class:`~messagefoundry.parsing.xml.errors.XmlParseError`
    when it is not well-formed, and :class:`~messagefoundry.parsing.xml.errors.XmlSecurityError` when
    it declares a DOCTYPE. Both are :class:`ValueError`, so a Handler's ``except ValueError`` still
    routes the message to the error path; the refusal stays loud rather than reading as a schema
    mismatch (BACKLOG #5537)."""
    xmlschema_mod = load_xmlschema()
    etree = load_lxml()
    schema = _build_schema(xmlschema_mod, schema_source)
    # Parse the document through OUR hardened parser, then validate the resulting tree — so the
    # untrusted body still goes through the XXE/DTD lockdown, not xmlschema's own loader.
    root = parse_bytes(document)
    reasons: list[str] = []
    for error in schema.iter_errors(root):
        # PHI-safe: the element path + xmlschema's reason category (its 'reason' can embed the value,
        # so we use the validator/path + the error *type*, not the raw reason text).
        path = getattr(error, "path", None) or "/"
        reasons.append(f"{path}: {type(error).__name__}")
    _ = etree  # ensure the extra is present for callers that re-serialize after validating
    return XmlSchemaResult(valid=not reasons, reasons=tuple(reasons))
