# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in XSD schema validation for the XML codec (``xmlschema`` behind the ``[xml]`` extra, BACKLOG
#31) — the XML analog of the X12 :func:`~messagefoundry.parsing.x12.validate.validate` strict tier.

A Handler calls :func:`validate_against` on demand against a local schema; **remote ``schemaLocation``
fetching is disabled** so a crafted document can't make the validator open a network connection (SSRF),
mirroring the no-network lockdown of :mod:`messagefoundry.parsing.xml.harden`. An inline schema opens
no file of its own beyond xmlschema's bundled copies of well-known namespaces, which either kind may
read, and a schema given as a path opens files only under its own directory or the ``schema_root`` its
caller names (:func:`_build_schema` says how).

**PHI rule:** a validation failure is reported with the failing element *path* and *reason category*
only (xmlschema's structural reason), never the offending element value.

Pure: no engine imports; the only network the validator could do (schema fetch) is disabled.
"""

from __future__ import annotations

import codecs
import email.message
import functools
import io
import ntpath
import os
import stat
import urllib.request
import urllib.response
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from messagefoundry.parsing.xml._deps import load_lxml, load_xmlschema
from messagefoundry.parsing.xml.errors import XmlSecurityError, XmlValidationError
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
    """Whether ``path`` is ``root`` or lies beneath it, compared as whole, ``normcase``d components."""
    path, root = os.path.normcase(path), os.path.normcase(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives, or one relative and one absolute
        return False


def _local(path: str) -> str | None:
    """``path`` made absolute, or ``None`` when it is a UNC or device path.

    Judged on the text alone, never on what the filesystem says it resolves to: ``abspath`` is lexical
    (``GetFullPathNameW`` on Windows opens nothing), and ``ntpath.splitdrive`` then names the drive. On
    POSIX a backslash is an ordinary file-name character, so only a path that ``abspath`` leaves with two
    leading slashes is refused there. ``realpath`` is not used anywhere here: on Windows
    it opens the path, which for a UNC path is an SMB connection, and it rewrites a mapped drive to the
    UNC path behind it and a long path to its ``\\\\?\\`` form, both of which this would then refuse. A
    ``\\\\?\\`` prefix on a drive letter is a local long path on Windows and is dropped here, then
    restored by :func:`_native` for a path too long to open without it; ``\\\\?\\UNC\\``, ``\\\\.\\``
    and any other two-separator drive are not local, nor is any on POSIX."""
    full = os.path.abspath(path)
    drive, rest = ntpath.splitdrive(full)
    if drive[:2] in ("\\\\", "//"):
        letter = drive[4:]
        if (
            os.name != "nt"
            or drive[2:4] not in ("?\\", "?/")
            or len(letter) != 2
            or letter[1] != ":"
        ):
            return None
        full = letter + rest
    return full


def _native(path: str) -> str:
    """``path`` as the OS should be handed it: a Windows drive path at or past ``_MAX_PATH`` gets back
    the ``\\\\?\\`` prefix :func:`_local` dropped, so it opens without ``LongPathsEnabled``."""
    if os.name == "nt" and len(path) >= _MAX_PATH and path[1:2] == ":":
        return "\\\\?\\" + path
    return path


#: The reparse-tag bit Windows sets on every tag that names another path: a symlink, a junction (which
#: ``S_ISLNK`` does not report) and others. The same bit ``pipeline/dr_backup.py`` reads; ``parsing/``
#: may not import it from there.
_NAME_SURROGATE = 0x20000000
_MAX_LINKS = 32
_MAX_PATH = 248  # CreateDirectory's limit, below MAX_PATH's 260, so a directory is covered too


def _is_link(st: os.stat_result) -> bool:
    """A symbolic link, or a Windows reparse point that names another path, such as a junction. A
    surrogate ``readlink`` cannot read raises there, so the load fails rather than follows it."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


def _link_target(link: str) -> str | None:
    """Where ``link`` points, as :func:`_local` judges the target text, without following it."""
    return _local(os.path.join(os.path.dirname(link), os.readlink(_native(link))))


def _resolve_within(path: str, root: str) -> str | None:
    """``path`` with every link below ``root`` replaced by its target, or ``None`` when one leads out.

    Walks the components below ``root`` one at a time with ``lstat``, so no link is followed before its
    target text is judged: one pointing at a UNC or device path, or outside ``root``, refuses the whole
    path before anything opens it. ``root`` itself is not walked; it is the operator's choice."""
    pending = os.path.relpath(path, root).split(os.sep)
    current, hops = root, 0
    while pending:
        part = pending.pop(0)
        if part in ("", os.curdir):
            continue
        candidate = os.path.join(current, part)
        if not _is_link(os.lstat(_native(candidate))):  # a missing file raises, as an open would
            current = candidate
            continue
        hops += 1
        target = _link_target(candidate)
        if hops > _MAX_LINKS or target is None or not _within(target, root):
            return None
        pending = os.path.relpath(target, root).split(os.sep) + pending
        current = root
    return current


def _read(path: str, *, no_follow: bool) -> bytes:
    # O_NOFOLLOW (POSIX only) refuses a final component swapped for a link after the walk checked it.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if no_follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(_native(path), flags), "rb") as fh:
        return fh.read()


#: The XSD elements that name another document to load. A location on one that holds a newline or
#: opens with ``<`` is not a URL to xmlschema, which parses it as an inline document; that never passes
#: the opener or ``parse_bytes``, so its DOCTYPE would take effect.
_XSD = "{http://www.w3.org/2001/XMLSchema}"
_LOADERS = tuple(f"{_XSD}{local}" for local in ("include", "import", "redefine", "override"))


def _refuse_text_locations(tree: Any) -> Any:
    """``tree``, once no include, import, redefine or override in it carries a location xmlschema would
    parse as XML text rather than open as a URL (its ``is_url``: a newline, or ``<`` first)."""
    for elem in tree.iter(*_LOADERS):
        location = elem.get("schemaLocation") or ""
        if "\n" in location or "\r" in location or location.lstrip().startswith("<"):
            raise XmlSecurityError("a schema location that is XML text, not a URL")
    return tree


@dataclass(frozen=True)
class _Root:
    """A directory reads are confined to, in :func:`_local` form. ``vet`` marks a root holding the
    caller's files: each is reached by :func:`_resolve_within` and checked by ``parse_bytes``."""

    path: str
    vet: bool


@functools.cache
def _bundled_root(module_file: str) -> tuple[_Root, ...]:
    """xmlschema's own ``schemas`` directory, which holds its copies of well-known namespaces. Empty
    when xmlschema is installed on a UNC path, which no root may be."""
    directory = _local(os.path.join(os.path.dirname(module_file), "schemas"))
    return () if directory is None else (_Root(directory, vet=False),)


class _ConfinedFiles(urllib.request.BaseHandler):
    """The only way xmlschema can open a resource here: ``file:`` URLs under fixed roots (BACKLOG #5537).

    Installed as xmlschema's ``opener``, so it sees every open xmlschema makes, of the schema file the
    caller named and of each include, import, redefine and override; every other scheme reaches
    ``unknown_open``. The named file is read as named, a link at it included. One
    root is xmlschema's bundled ``schemas`` directory, which holds the copies of well-known namespaces
    (SOAP encoding, XML-DSig, xlink and others) a location-free ``xs:import`` resolves to; those are
    library files and are read as they are, links included. For a schema given as a path, the other
    root is its own directory, or the ``schema_root`` the caller named. Each file under it is reached by
    :func:`_resolve_within` and checked by :func:`~messagefoundry.parsing.xml.harden.parse_bytes`
    first, so a path schema's includes meet the same DOCTYPE refusal as an inline schema. Anything else,
    and a refused link or a DOCTYPE there, raises xmlschema's own ``XMLResourceBlocked``: an include
    then fails the build, and an import is skipped with a warning and falls back to its next location,
    such as a bundled copy. A missing file still raises ``FileNotFoundError``, which xmlschema reports
    for an include as a warning, as it always has.

    The location is judged on its text by :func:`_local`, then compared with each root by whole
    components, so a sibling directory sharing a name prefix (``schemas-old`` beside ``schemas``) is
    outside. Only then is any of it touched, by the ``lstat`` walk."""

    def __init__(
        self, blocked: type[Exception], roots: tuple[_Root, ...], entry: str | None = None
    ) -> None:
        self._blocked = blocked
        self._roots = roots
        self._entry = None if entry is None else os.path.normcase(entry)

    def file_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        url = req.full_url
        parts = urlsplit(url)
        written = _local(urllib.request.url2pathname(parts.path))
        if parts.netloc.lower() in ("", "localhost") and written is not None:
            if os.path.normcase(written) == self._entry:
                # The file the caller named is read as named, a link at it included; a DOCTYPE or
                # text location in it raises unconverted, since the build has nowhere to fall back to.
                data = _read(written, no_follow=False)
                _refuse_text_locations(parse_bytes(data))
                return urllib.response.addinfourl(io.BytesIO(data), email.message.Message(), url)
            for root in self._roots:
                if not _within(written, root.path):
                    continue
                if not root.vet:
                    data = _read(written, no_follow=False)
                    return urllib.response.addinfourl(
                        io.BytesIO(data), email.message.Message(), url
                    )
                try:
                    checked = _resolve_within(written, root.path)
                    if checked is None:
                        break  # a link out of the root, or to a UNC or device path
                    data = _read(checked, no_follow=True)
                    _refuse_text_locations(parse_bytes(data))  # the tree is discarded
                except FileNotFoundError:
                    raise  # a missing file, as xmlschema has always reported it
                except (OSError, ValueError) as exc:
                    # Blocked, not an OSError or a ValueError: xmlschema drops an include that raises
                    # OSError with only a warning, and stops the whole build on a ValueError where an
                    # import would otherwise fall back to its next location, such as a bundled copy.
                    # ValueError covers the parse_bytes refusals and a reparse point readlink rejects.
                    raise self._blocked(
                        "block a refused link, or a file parse_bytes refuses"
                    ) from exc
                return urllib.response.addinfourl(io.BytesIO(data), email.message.Message(), url)
        # PHI-safe: names no part of the location. xmlschema adds the URL to its own warning.
        raise self._blocked("block access to a resource outside the schema's confinement root")

    def unknown_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        # allow="local" refuses a remote URL first; this keeps any scheme it lets through from reaching
        # OpenerDirector's no-handler path, which returns None and surfaces as an AttributeError.
        raise self._blocked("block access to a resource that is not a local file")


class _SourceRefused(ValueError):
    """A schema source or ``schema_root`` this module refuses. Its message is fixed text, never the
    path, so :func:`_build_schema` may repeat it."""


def _local_path(text: str | bytes | os.PathLike[str], what: str) -> str:
    """The absolute local path ``text`` names: a filesystem path, or a ``file:`` URL with no host. A
    remote URL, another scheme, or a UNC or device path is refused on its text; ``what`` names the
    argument in the refusal. Directories are taken as written, so a mapped drive stays a drive letter."""
    source = os.fsdecode(text).strip()
    if not source:  # abspath would make it the working directory
        raise _SourceRefused(f"{what} that is empty")
    parts = urlsplit(source)
    scheme = parts.scheme.lower()
    if scheme == "file":
        if parts.netloc.lower() not in ("", "localhost"):
            raise _SourceRefused(f"{what} that is a file URL naming a host")
        source = urllib.request.url2pathname(parts.path)
    elif scheme and not (len(scheme) == 1 and source[1:2] == ":"):  # a drive letter is not a scheme
        raise _SourceRefused(f"{what} that is not a local path")
    local = _local(source)
    if local is None:
        raise _SourceRefused(f"{what} that is a UNC or device path")
    return local


def _confinement_root(source: str, schema_root: str | os.PathLike[str] | None) -> _Root:
    """The directory a path schema's reads are confined to: ``schema_root`` when given, which must hold
    the schema, else the schema's own directory. A schema at a filesystem root with no ``schema_root``
    is confined to itself, since its directory would be every file on that volume."""
    if schema_root is not None:
        root = _local_path(schema_root, "a schema_root")
        if not _within(source, root):
            raise _SourceRefused("a schema that does not lie under schema_root")
        return _Root(root, vet=True)
    directory = os.path.dirname(source)
    return _Root(source if os.path.dirname(directory) == directory else directory, vet=True)


def _build_schema(
    xmlschema_mod: Any,
    schema_source: str | bytes | os.PathLike[str],
    schema_root: str | os.PathLike[str] | None = None,
) -> Any:
    """Construct an ``xmlschema.XMLSchema`` that opens no file outside its confinement root.

    An **inline** schema is parsed by :func:`~messagefoundry.parsing.xml.harden.parse_bytes` first, so
    the XSD goes through the same lockdown as every other document and xmlschema is handed an
    already-hardened tree instead of raw text (ASVS 1.5.3). Without that it parsed the source with its
    own **non-defused** ElementTree: an XSD carrying
    ``<!DOCTYPE xs:schema [<!ENTITY nm "patient">]>`` was parsed and its internal entity **expanded**,
    while ``parse_bytes`` refuses a DOCTYPE outright. An inline schema has no directory, so its own
    include, import, redefine or override location is opened only when it names a file in xmlschema's
    bundled ``schemas`` directory; any other, local or remote, is refused: an include or a redefine that
    needs one fails the build, and an import that needs one is skipped, so a type only it defines fails
    the build. ``schema_root`` is refused for an inline schema.

    A schema given as a **path** (or a host-less ``file:`` URL) is read as the caller named it, a link
    at that name included, and checked by ``parse_bytes``. What it includes is opened only under its
    confinement root, each file checked the same way: its own directory, or ``schema_root`` when the
    caller names one, for a bundle such as HL7 CDA R2 whose schemas include across sibling directories
    (``../../processable/coreschemas/...``). Its includes resolve beside the name as written.

    Both rely on :class:`_ConfinedFiles` as xmlschema's opener, with ``allow="local"`` so xmlschema
    refuses a remote URL before it reaches the opener, and ``defuse="always"`` so its own entity check
    runs on every file as well. Before BACKLOG #5537 this was ``allow="local"`` with no opener and the
    default ``defuse="remote"``, and an inline schema's ``xs:include`` of a ``file:`` URL read that local
    file and expanded a DOCTYPE entity inside it. xmlschema's ``allow="sandbox"`` is not used: it
    compares URL string prefixes, and it narrows to each includer's own directory, so a nested include
    that climbs back inside the top-level directory was refused.
    """
    blocked = xmlschema_mod.exceptions.XMLResourceBlocked
    roots = _bundled_root(xmlschema_mod.__file__)
    try:
        entry = None
        if isinstance(schema_source, (str, bytes)) and _is_inline_xml(schema_source):
            if schema_root is not None:
                raise _SourceRefused("a schema_root given with an inline schema")
            source: Any = _refuse_text_locations(parse_bytes(schema_source))
        else:
            entry = _local_path(schema_source, "a schema location")
            roots += (_confinement_root(entry, schema_root),)
            # A file URL, not the bare path: xmlschema decodes a path's %XX a second time, and keeps
            # a URL's identity, so an include that includes the entry back is not loaded twice.
            source = Path(entry).as_uri()
        opener = urllib.request.OpenerDirector()
        opener.add_handler(_ConfinedFiles(blocked, roots, entry))
        return xmlschema_mod.XMLSchema(source, allow="local", defuse="always", opener=opener)
    except _SourceRefused as exc:
        raise XmlValidationError(f"could not load XSD schema: {exc}") from exc
    except Exception as exc:  # xmlschema (and now harden) raise their own hierarchies
        # The exception TYPE names which gate refused it (XmlSecurityError = the XSD carried a
        # DOCTYPE) without quoting the schema text. Keeps validate_against's documented contract:
        # a schema that cannot be loaded is always XmlValidationError.
        raise XmlValidationError(f"could not load XSD schema: {type(exc).__name__}") from exc


def validate_against(
    document: str | bytes,
    schema_source: str | bytes | os.PathLike[str],
    *,
    schema_root: str | os.PathLike[str] | None = None,
) -> XmlSchemaResult:
    """Validate ``document`` against the XSD ``schema_source`` (a schema string/bytes or a local path).

    ``schema_root`` (a path or a host-less ``file:`` URL) widens what a schema given as a path may
    include, from its own directory to the whole of ``schema_root``: pass the top of a multi-directory
    bundle such as HL7 CDA R2. :func:`_build_schema` says what each file read must pass. It is refused
    for an inline schema, and for a schema that does not lie under it.

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
    schema = _build_schema(xmlschema_mod, schema_source, schema_root)
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
