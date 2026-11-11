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
import errno
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
from messagefoundry.parsing.xml.errors import XmlParseError, XmlSecurityError, XmlValidationError
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
        # A path never holds a NUL, and UTF-16/32 text without a BOM holds one in every ASCII char.
        return (
            schema_source.startswith(_BOMS)
            or schema_source.lstrip()[:1] == b"<"
            or b"\x00" in schema_source
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
    and any other two-separator drive are not local, nor is any on POSIX. Neither is ``\\\\?\\C:``
    with nothing rooted after it, the volume device itself."""
    full = os.path.abspath(path)
    drive, rest = ntpath.splitdrive(full)
    if drive[:2] in ("\\\\", "//"):
        letter = drive[4:]
        if (
            os.name != "nt"
            or drive[2:4] not in ("?\\", "?/")
            or len(letter) != 2
            or letter[1] != ":"
            or rest[:1] not in ("\\", "/")
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


def _runs_through_a_file(path: str, root: str) -> bool:
    """Whether the deepest existing parent of ``path`` at or below ``root`` is not a directory, links
    followed. Windows reports a path that runs on through a file as missing, where POSIX raises
    ``NotADirectoryError``; this tells the two apart on Windows. Used only for xmlschema's bundled
    root, whose links are library files; a vetted root is walked by :func:`_resolve_within`."""
    parent = os.path.dirname(path)
    while _within(parent, root):
        try:
            return not stat.S_ISDIR(os.stat(_native(parent)).st_mode)
        except FileNotFoundError:
            if os.path.dirname(parent) == parent:  # a filesystem root; never a bundled root
                return False
            parent = os.path.dirname(parent)
        except (OSError, ValueError):  # unreadable: not shown to be a file, so the miss stands
            return False
    return False


def _link_target(link: str) -> str | None:
    """Where ``link`` points, as :func:`_local` judges the target text, without following it."""
    return _local(os.path.join(os.path.dirname(link), os.readlink(_native(link))))


def _not_a_directory() -> NotADirectoryError:
    return NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))


def _resolve_within(path: str, root: str) -> str | None:
    """``path`` with every link below ``root`` replaced by its target, or ``None`` when one leads out.

    Walks the components below ``root`` one at a time with ``lstat``, so no link is followed before its
    target text is judged: one pointing at a UNC or device path, or outside ``root``, refuses the whole
    path before anything opens it. ``root`` itself is not walked for links; it is the operator's choice.

    A path that runs on through an existing file that is not a directory, ``root`` included, raises
    ``NotADirectoryError``. POSIX raises that itself, while Windows reports such a path as missing, and
    xmlschema skips a missing include or import with only a warning."""
    pending = os.path.relpath(path, root).split(os.sep)
    if pending != [os.curdir] and not stat.S_ISDIR(os.stat(_native(root)).st_mode):
        raise _not_a_directory()  # a schema at a filesystem root is confined to itself, a file
    current, hops = root, 0
    while pending:
        part = pending.pop(0)
        if part in ("", os.curdir):
            continue
        candidate = os.path.join(current, part)
        st = os.lstat(_native(candidate))  # a missing file raises, as an open would
        if not _is_link(st):
            if pending and not stat.S_ISDIR(st.st_mode):
                raise _not_a_directory()
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
    """The bytes of the regular file at ``path``. Any other file that opens raises an ``OSError``
    once open; a path that cannot be opened raises what ``os.open`` raises, which is a ``ValueError``
    for a NUL in it.

    On POSIX ``os.open`` succeeds on a directory or a device, and ``os.fdopen`` then raised without
    closing the descriptor it was handed, so each such location leaked one. A FIFO with no writer
    blocked the open itself; ``O_NONBLOCK`` (POSIX only) lets that open return. ``fstat`` then refuses
    every non-regular file before any read, so a device such as ``/dev/zero`` is never read without
    end, and the descriptor is closed on every path."""
    # O_NOFOLLOW (POSIX only) refuses a final component swapped for a link after the walk checked it.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if no_follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(_native(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


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


def _file_url_path(url: str) -> str | None:
    """The local path a host-less ``file:`` URL names, in :func:`_local` form, else ``None``."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "file" or parts.netloc.lower() not in ("", "localhost"):
        return None
    return _local(urllib.request.url2pathname(parts.path))


class _ResourceRefused(ValueError):
    """A resource :class:`_ConfinedFiles` refuses to hand xmlschema. Not an ``OSError`` and not one of
    xmlschema's resource errors, so neither its include path nor its import path catches it and the
    build stops; :func:`_fallback_loader` alone turns it into a skipped import. Its message is fixed
    text, never the location, so :func:`_build_schema` may repeat it; ``url`` is the refused URL, for
    that comparison only."""

    def __init__(self, message: str, url: str) -> None:
        super().__init__(message)
        self.url = url


def _same_resource(url: str, other: str) -> bool:
    """Whether two URLs name the same resource: the same local path where both are host-less ``file:``
    URLs, else the same text. A mismatch only withholds a fallback, so it errs closed."""
    path = _file_url_path(url)
    return url == other or (path is not None and path == _file_url_path(other))


@functools.cache
def _fallback_loader(xmlschema_mod: Any, bundled: tuple[_Root, ...]) -> type:
    """xmlschema's ``SchemaLoader`` with one change: an import whose own location the opener refused is
    skipped, so xmlschema tries its next location, only when one of those locations is a bundled copy
    of the namespace (BACKLOG #5537). The stock W3C ``xmldsig-core-schema.xsd`` carries a DOCTYPE, and
    SAML and WS-Security bundles import it by a local location; xmlschema's own copy then stands in.

    Any other refusal stops the build, one met while loading a file the import did open included: the
    partly loaded file would stay registered beside the bundled copy. Skipped, an import would leave
    the namespace undeclared, and a ``lax`` or ``skip`` wildcard would admit its content unchecked."""
    blocked = xmlschema_mod.exceptions.XMLResourceBlocked

    def has_bundled_copy(loader: Any, namespace: str, location: str) -> bool:
        for url in loader.get_locations(namespace):
            path = None if url == location else _file_url_path(url)
            if path is not None and any(_within(path, root.path) for root in bundled):
                return True
        return False

    def import_schema(
        self: Any, target_schema: Any, namespace: str, location: str, *args: Any, **kwargs: Any
    ) -> Any:
        try:
            return base.import_schema(self, target_schema, namespace, location, *args, **kwargs)
        except _ResourceRefused as exc:
            if not _same_resource(exc.url, location) or not has_bundled_copy(
                self, namespace, location
            ):
                raise
            raise blocked("block a refused import that a bundled copy stands in for") from exc

    base = xmlschema_mod.SchemaLoader
    return type("_FallbackLoader", (base,), {"import_schema": import_schema})


class _ConfinedFiles(urllib.request.BaseHandler):
    """The only way xmlschema can open a resource here: ``file:`` URLs under fixed roots (BACKLOG #5537).

    Installed as xmlschema's ``opener``, so it sees every location xmlschema opens as a URL, the schema
    file the caller named and each include, import, redefine and override location among them; every
    scheme but ``file:`` reaches ``unknown_open``. It does not see every location a schema names: one
    xmlschema reads as XML text is parsed, not opened, so :func:`_refuse_text_locations` refuses it
    first, and ``allow="local"`` refuses a remote URL before it is opened. The named file is read as
    named, a link at it included. One root is xmlschema's bundled ``schemas`` directory, which holds
    the copies of well-known namespaces (SOAP encoding, XML-DSig, xlink and others) a location-free
    ``xs:import`` resolves to; those are library files and are read as they are, links included. For
    a schema given as a path, the other root is its own directory, or the ``schema_root`` the caller
    named. Each file under it is reached by
    :func:`_resolve_within` and checked by :func:`~messagefoundry.parsing.xml.harden.parse_bytes`
    first, so a path schema's includes meet the same DOCTYPE refusal as an inline schema. A location
    outside every root, or one that is not a local file path, such as a UNC or device path, raises
    :class:`_ResourceRefused`. So, under any root, the bundled one included, does a location that
    cannot be read as a file, such as a directory, a FIFO or device, a path that runs on through a
    file, or one the process may not read; and, under a
    vetted root, does at least a link the walk refuses, one reached through a link it cannot read, and
    a file ``parse_bytes`` or :func:`_refuse_text_locations` refuses. A missing file raises
    ``FileNotFoundError``. :func:`_build_schema` says what each does to the build.

    The location is judged on its text by :func:`_local`, then compared with each root by whole
    components, so a sibling directory sharing a name prefix (``schemas-old`` beside ``schemas``) is
    outside. Only then is any of it touched, by the ``lstat`` walk."""

    def __init__(self, roots: tuple[_Root, ...], entry: str | None = None) -> None:
        self._roots = roots
        self._entry = entry

    def file_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        url = req.full_url
        written = _file_url_path(url)
        if written is not None:
            # The exact text, not a normcase'd form: in a case-sensitive Windows directory a sibling
            # differing only in case is another file, and it must take the walk below.
            if written == self._entry:
                # The file the caller named is read as named, a link at it included; a DOCTYPE or
                # text location in it raises unconverted, since the build has nowhere to fall back to.
                data = _read(written, no_follow=False)
                _refuse_text_locations(parse_bytes(data))
                return urllib.response.addinfourl(io.BytesIO(data), email.message.Message(), url)
            for root in self._roots:
                if not _within(written, root.path):
                    continue
                # Each refusal below is _ResourceRefused, not an OSError: xmlschema drops an include
                # or an import that raises OSError with only a warning, and a lax wildcard would then
                # admit that namespace unchecked. That holds for a directory in the bundled root too.
                # Every reason is fixed text.
                try:
                    if not root.vet:  # library files, read as they are, links included
                        through_a_file = False
                        try:
                            data = _read(written, no_follow=False)
                        except FileNotFoundError:
                            if not _runs_through_a_file(written, root.path):
                                raise  # a missing file, as xmlschema has always reported it
                            through_a_file = True
                        if through_a_file:  # raised outside the handler, so nothing is chained
                            raise _not_a_directory()
                        return urllib.response.addinfourl(
                            io.BytesIO(data), email.message.Message(), url
                        )
                    checked = _resolve_within(written, root.path)
                    if checked is None:
                        raise _ResourceRefused(
                            "a resource reached through a link that leads out of the root, to a UNC"
                            f" or device path, or through more than {_MAX_LINKS} links",
                            url,
                        )
                    data = _read(checked, no_follow=True)
                    _refuse_text_locations(parse_bytes(data))  # the tree is discarded
                except (FileNotFoundError, _ResourceRefused):
                    raise  # a missing file, as xmlschema has always reported it, or the refusal above
                except XmlSecurityError as exc:  # parse_bytes, or _refuse_text_locations
                    raise _ResourceRefused(
                        "a file that declares a DOCTYPE, or names a location that is XML text", url
                    ) from exc
                except XmlParseError as exc:  # parse_bytes: malformed or empty
                    raise _ResourceRefused("a file that is not well-formed XML", url) from exc
                except (OSError, ValueError) as exc:  # after the two above, which are ValueErrors
                    # A directory, a FIFO or device, a path that runs on through a file, a denied
                    # read, a link lstat or readlink cannot read (readlink raises ValueError for a
                    # reparse point it rejects), or a NUL in the path.
                    raise _ResourceRefused("a location that cannot be read as a file", url) from exc
                return urllib.response.addinfourl(io.BytesIO(data), email.message.Message(), url)
        # PHI-safe: names no part of the location.
        if written is None:  # a host on the URL, or _local refused a UNC or device path
            raise _ResourceRefused("a resource that is not a local file path", url)
        raise _ResourceRefused("a resource outside the schema's confinement root", url)

    def unknown_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        # allow="local" refuses a remote URL first; this keeps any scheme it lets through from reaching
        # OpenerDirector's no-handler path, which returns None and surfaces as an AttributeError.
        raise _ResourceRefused("a resource that is not a local file", req.full_url)


class _SourceRefused(ValueError):
    """A schema source or ``schema_root`` this module refuses. Its message is fixed text, never the
    path, so :func:`_build_schema` may repeat it."""


def _local_path(text: str | bytes | os.PathLike[str], what: str) -> str:
    """The absolute local path ``text`` names: a filesystem path, or a ``file:`` URL with no host. A
    remote URL, another scheme, a Windows drive-relative path, or a UNC or device path is refused on
    its text; ``what`` names the argument in the refusal. Directories are taken as written, so a mapped
    drive stays a drive letter.

    A relative path resolves against the working directory, as xmlschema resolved it before BACKLOG
    #5537; under the shipped Windows service that is the engine install root. On Windows, a path
    rooted with no drive, such as ``/opt/x.xsd``, takes the working directory's drive, as it did then
    too, and a drive-relative path (``C:``, ``C:.``, ``C:foo``, ``file:///C:``, ``file:C:``) is
    refused: it resolves against that drive's own current directory, which is the working directory
    only when it is on that drive and otherwise a per-drive setting nobody sees, so its text does not
    say which directory it names. On POSIX, ``C:foo`` is an ordinary relative file name."""
    source = os.fsdecode(text).strip()
    if not source:  # names no path; abspath would supply the working directory, which "." names
        raise _SourceRefused(f"{what} that is empty")
    parts = urlsplit(source)
    scheme = parts.scheme.lower()
    if scheme == "file":
        if parts.netloc.lower() not in ("", "localhost"):
            raise _SourceRefused(f"{what} that is a file URL naming a host")
        source = urllib.request.url2pathname(parts.path).strip()
        if not source:  # "file:" or "file://localhost" names no path, so none is supplied
            raise _SourceRefused(f"{what} that is a file URL naming no path")
    elif scheme and not (len(scheme) == 1 and source[1:2] == ":"):  # a drive letter is not a scheme
        raise _SourceRefused(f"{what} that is not a local path")
    if os.name == "nt":
        drive, rest = ntpath.splitdrive(source)
        if len(drive) == 2 and drive[1] == ":" and rest[:1] not in ("\\", "/"):
            raise _SourceRefused(f"{what} that is a drive-relative path")
    local = _local(source)
    if local is None:
        raise _SourceRefused(f"{what} that is a UNC or device path")
    return local


def _confinement_root(source: str, schema_root: str | os.PathLike[str] | None) -> _Root:
    """The directory a path schema's reads are confined to: ``schema_root`` when given, which must hold
    the schema, else the schema's own directory. A schema at a filesystem root with no ``schema_root``
    is confined to itself, and a ``schema_root`` that is a filesystem root is refused, since either
    would make every file on that volume readable."""
    if schema_root is not None:
        root = _local_path(schema_root, "a schema_root")
        if os.path.dirname(root) == root:
            raise _SourceRefused("a schema_root that is a filesystem root")
        if not _within(source, root):
            raise _SourceRefused("a schema that does not lie under schema_root")
        return _Root(root, vet=True)
    directory = os.path.dirname(source)
    return _Root(source if os.path.dirname(directory) == directory else directory, vet=True)


def _build_schema(
    xmlschema_mod: Any,
    schema_source: str | bytes | bytearray | os.PathLike[str],
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
    bundled ``schemas`` directory. ``schema_root`` is refused for an inline schema.

    A schema given as a **path** (or a host-less ``file:`` URL) is read as the caller named it, a link
    at that name included, and checked by ``parse_bytes``. What it includes is opened only under its
    confinement root, each file checked the same way: its own directory, or ``schema_root`` when the
    caller names one, for a bundle such as HL7 CDA R2 whose schemas include across sibling directories
    (``../../processable/coreschemas/...``). Its includes resolve beside the name as written. A
    relative path or ``schema_root`` resolves against the working directory; a Windows
    drive-relative one, such as ``C:`` or ``C:foo``, is refused on its text (:func:`_local_path` says
    why).

    **A refused location** is at least: a local one outside those bounds; one reached through a link
    out of the root, to a UNC or device path, or through more than ``_MAX_LINKS`` links; a UNC or
    device path itself; one that cannot be read as a file, such as a directory, a FIFO or device, a
    path that runs on through a file (on every platform), or a file the process
    may not read; a file there that ``parse_bytes`` refuses (a DOCTYPE, malformed or empty); and a
    location xmlschema would parse as XML text rather than open. It fails the build, and the error
    repeats the refusal's fixed reason where the refusal has one. The one exception is an import's
    own location, when xmlschema bundles a copy of the
    imported namespace: the import then falls back to that copy, as the stock W3C XML-DSig schema with
    its DOCTYPE needs. A refusal met further in, inside a file such an import did open, still fails the
    build. A **remote** location never reaches the opener; ``allow="local"`` refuses it first, which
    fails the build on an include, redefine or override, and on an import makes xmlschema skip that
    location with a warning and try the next, as it did before BACKLOG #5537. A **missing** file is
    handled by xmlschema as it always was: an include or an import of one is skipped with a warning,
    and a redefine or override that carries components fails. A skipped import with no location left
    leaves its namespace undeclared: a reference to one of its types fails the build, but a ``lax`` or
    ``skip`` wildcard admits that namespace's elements unchecked.

    Both rely on :class:`_ConfinedFiles` as xmlschema's opener, with ``allow="local"`` so xmlschema
    refuses a remote URL before it reaches the opener, and ``defuse="always"`` so its own entity check
    runs on every file as well. Before BACKLOG #5537 this was ``allow="local"`` with no opener and the
    default ``defuse="remote"``, and an inline schema's ``xs:include`` of a ``file:`` URL read that local
    file and expanded a DOCTYPE entity inside it. xmlschema's ``allow="sandbox"`` is not used: it
    compares URL string prefixes, and it narrows to each includer's own directory, so a nested include
    that climbs back inside the top-level directory was refused.
    """
    bundled = _bundled_root(xmlschema_mod.__file__)
    roots = bundled
    if isinstance(schema_source, bytearray):
        schema_source = bytes(schema_source)
    try:
        entry = None
        if isinstance(schema_source, (str, bytes)) and _is_inline_xml(schema_source):
            if schema_root is not None:
                raise _SourceRefused("a schema_root given with an inline schema")
            source: Any = _refuse_text_locations(parse_bytes(schema_source))
        else:
            entry = _local_path(schema_source, "a schema location")
            roots = (*bundled, _confinement_root(entry, schema_root))
            # A file URL, not the bare path: xmlschema decodes a path's %XX a second time, and keeps
            # a URL's identity, so an include that includes the entry back is not loaded twice.
            source = Path(entry).as_uri()
        opener = urllib.request.OpenerDirector()
        opener.add_handler(_ConfinedFiles(roots, entry))
        return xmlschema_mod.XMLSchema(
            source,
            allow="local",
            defuse="always",
            opener=opener,
            loader_class=_fallback_loader(xmlschema_mod, bundled),
        )
    except (_SourceRefused, _ResourceRefused) as exc:
        raise XmlValidationError(f"could not load XSD schema: {exc}") from exc
    except Exception as exc:  # xmlschema (and now harden) raise their own hierarchies
        # The exception TYPE names which gate refused it (XmlSecurityError = the XSD carried a
        # DOCTYPE) without quoting the schema text. Keeps validate_against's documented contract:
        # a schema that cannot be loaded is always XmlValidationError.
        raise XmlValidationError(f"could not load XSD schema: {type(exc).__name__}") from exc


def validate_against(
    document: str | bytes,
    schema_source: str | bytes | bytearray | os.PathLike[str],
    *,
    schema_root: str | os.PathLike[str] | None = None,
) -> XmlSchemaResult:
    """Validate ``document`` against the XSD ``schema_source`` (a schema string/bytes or a local path).

    ``schema_root`` (a path or a host-less ``file:`` URL naming one; a relative one resolves against
    the working directory, and a Windows drive-relative one is refused) widens what a schema given as
    a path may include, from its own directory to the whole of ``schema_root``: pass the top of a
    multi-directory bundle such as HL7 CDA R2. :func:`_build_schema` says what each file read must
    pass. It is refused for an inline schema, and for a schema that does not lie under it.

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
    try:
        for error in schema.iter_errors(root):
            # PHI-safe: the element path + xmlschema's reason category (its 'reason' can embed the
            # value, so we use the validator/path + the error *type*, not the raw reason text).
            path = getattr(error, "path", None) or "/"
            reasons.append(f"{path}: {type(error).__name__}")
    except _ResourceRefused as exc:
        # xmlschema may load a namespace while validating (a wildcard meeting a namespace it holds
        # a location for); a refusal there is the schema failing to load, never a valid result.
        raise XmlValidationError(f"could not load XSD schema: {exc}") from exc
    _ = etree  # ensure the extra is present for callers that re-serialize after validating
    return XmlSchemaResult(valid=not reasons, reasons=tuple(reasons))
