# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``validate_against`` reads no resource beyond the schema it is given (BACKLOG #5537).

Three limbs, each pinned against the behaviour it replaces:

* a schema opening with a byte-order mark is the schema DOCUMENT, not a path, so it goes through the
  hardened pre-parse. A BOM-prefixed ``bytes`` schema used to skip that pre-parse, and xmlschema then
  expanded a DOCTYPE entity in it;
* every location xmlschema opens as a URL goes through ``schema._ConfinedFiles``, xmlschema's
  opener, and one it would parse as XML text is refused before it: an inline schema opens none
  of its own locations outside xmlschema's bundled copies of well-known namespaces, which either kind
  may read, and a path schema opens files only under its own directory or the ``schema_root`` its
  caller names, each checked by ``parse_bytes`` and reached without following a link out of that root
  or to a UNC or device path. ``allow="local"`` still refuses a remote URL before the opener sees it;
* a malformed or DOCTYPE ``document`` raises the hardened parser's error rather than returning an
  invalid result, and the docstring now says so.

Every file a test writes is under ``tmp_path``; nothing depends on the process's working directory
except the tests that set it with ``monkeypatch.chdir``: those on relative, drive-relative and
rooted paths with no drive.
"""

from __future__ import annotations

import codecs
import gc
import os
import stat
import sys
import urllib.request
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("lxml")
pytest.importorskip("xmlschema")

from messagefoundry.parsing.xml.errors import (  # noqa: E402 - after importorskip
    XmlParseError,
    XmlSecurityError,
    XmlValidationError,
)
from messagefoundry.parsing.xml.schema import validate_against  # noqa: E402

_XS = 'xmlns:xs="http://www.w3.org/2001/XMLSchema"'
_CLEAN = f'<xs:schema {_XS}><xs:element name="patient" type="xs:string"/></xs:schema>'
#: Loads only if its internal entity is expanded: the element is named through it.
_ENTITY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE xs:schema [<!ENTITY nm "patient">]>'
    f'<xs:schema {_XS}><xs:element name="&nm;" type="xs:string"/></xs:schema>'
)


def _causes(exc: BaseException) -> list[str]:
    names = []
    cur: BaseException | None = exc
    while cur is not None:
        names.append(type(cur).__name__)
        cur = cur.__cause__
    return names


# --- limb 1: a byte-order mark does not turn a schema into a path ------------------------------


@pytest.mark.parametrize(
    "schema",
    [
        pytest.param("\N{BYTE ORDER MARK}" + _CLEAN, id="str-bom"),
        pytest.param(codecs.BOM_UTF8 + _CLEAN.encode("utf-8"), id="utf8-bom-bytes"),
        pytest.param(codecs.BOM_UTF16_LE + _CLEAN.encode("utf-16-le"), id="utf16le-bom-bytes"),
        pytest.param(codecs.BOM_UTF16_BE + _CLEAN.encode("utf-16-be"), id="utf16be-bom-bytes"),
    ],
)
def test_bom_prefixed_schema_is_read_as_the_schema(schema: str | bytes) -> None:
    # On origin/main the str form raised XmlValidationError (it was opened as a file name).
    assert validate_against("<patient>x</patient>", schema).valid
    assert not validate_against("<other>x</other>", schema).valid


def test_bom_prefixed_bytes_schema_with_a_doctype_is_refused() -> None:
    # The bypass, worse than the row filed it. On origin/main the BOM sent these bytes past
    # parse_bytes, xmlschema parsed them itself, expanded &nm; and returned valid=True.
    schema = codecs.BOM_UTF8 + _ENTITY.encode("utf-8")
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", schema)
    assert "XmlSecurityError" in _causes(ei.value)
    # Control: the same schema with no BOM was already refused by the same gate.
    with pytest.raises(XmlValidationError) as ei2:
        validate_against("<patient>x</patient>", _ENTITY.encode("utf-8"))
    assert "XmlSecurityError" in _causes(ei2.value)


# --- limb 2: an inline schema opens nothing; a path schema stays in its directory ---------------


def test_inline_schema_include_of_a_local_file_is_refused(tmp_path: Path) -> None:
    inc = tmp_path / "inc.xsd"
    inc.write_text(_CLEAN, encoding="utf-8")
    schema = f'<xs:schema {_XS}><xs:include schemaLocation="{inc.as_uri()}"/></xs:schema>'
    # On origin/main allow="local" opened inc.xsd and the include defined <patient>: valid=True.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", schema)
    assert "_ResourceRefused" in _causes(ei.value)
    # Control: the included file itself is a sound schema, so the refusal is the include.
    assert validate_against("<patient>x</patient>", str(inc)).valid


def test_inline_schema_import_of_a_local_file_is_not_opened(tmp_path: Path) -> None:
    other = tmp_path / "other.xsd"
    other.write_text(
        f'<xs:schema {_XS} targetNamespace="urn:o"><xs:simpleType name="Id">'
        '<xs:restriction base="xs:string"/></xs:simpleType></xs:schema>',
        encoding="utf-8",
    )
    schema = (
        f'<xs:schema {_XS} xmlns:o="urn:o">'
        f'<xs:import namespace="urn:o" schemaLocation="{other.as_uri()}"/>'
        '<xs:element name="patient" type="o:Id"/></xs:schema>'
    )
    # urn:o has no bundled copy, so the refused import fails the build itself rather than being
    # skipped. On origin/main the import read other.xsd and the schema loaded.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", schema)
    assert "_ResourceRefused" in _causes(ei.value)


def test_inline_schema_still_resolves_a_namespace_xmlschema_already_holds() -> None:
    # Anti-vacuity for the confinement: a location-free import of the xml namespace needs no resource.
    schema = (
        f'<xs:schema {_XS} targetNamespace="urn:t">'
        '<xs:import namespace="http://www.w3.org/XML/1998/namespace"/>'
        '<xs:element name="e"><xs:complexType><xs:attribute ref="xml:lang"/></xs:complexType>'
        "</xs:element></xs:schema>"
    )
    assert validate_against('<t:e xmlns:t="urn:t" xml:lang="en"/>', schema).valid


def _bundled_directory() -> Path:
    import xmlschema

    directory = Path(xmlschema.__file__).parent / "schemas" / "DSIG"
    assert directory.is_dir()  # anti-vacuity: a real directory inside the bundled root
    return directory


@pytest.mark.parametrize("element", ["include", "import"])
def test_an_unreadable_location_in_the_bundled_schemas_fails_the_build(element: str) -> None:
    # Before the fix the opener read the bundled root unguarded, so opening a directory there raised
    # an OSError, xmlschema skipped the include or import with a warning, and a lax wildcard then
    # admitted urn:x unchecked: valid=True.
    location = _bundled_directory().as_uri()
    loader = (
        f'<xs:import namespace="urn:x" schemaLocation="{location}"/>'
        if element == "import"
        else f'<xs:include schemaLocation="{location}"/>'
    )
    schema = (
        f'<xs:schema {_XS} targetNamespace="urn:t">{loader}'
        '<xs:element name="e"><xs:complexType><xs:sequence>'
        '<xs:any namespace="urn:x" processContents="lax"/>'
        "</xs:sequence></xs:complexType></xs:element></xs:schema>"
    )
    with pytest.raises(XmlValidationError, match="a location that cannot be read as a file") as ei:
        validate_against('<t:e xmlns:t="urn:t"><x:v xmlns:x="urn:x">1</x:v></t:e>', schema)
    assert "DSIG" not in str(ei.value)  # PHI-safe: the location is not quoted


# The inline remote-include refusal is pinned in tests/test_xml_parser_consistency.py
# (test_xmlschema_still_disables_remote_schema_resolution); the path one is below.


def _write_path_schema(directory: Path, include: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    main = directory / "main.xsd"
    main.write_text(
        f'<xs:schema {_XS}><xs:include schemaLocation="{include}"/></xs:schema>', encoding="utf-8"
    )
    return main


def test_path_schema_includes_a_sibling_and_a_subdirectory(tmp_path: Path) -> None:
    (tmp_path / "schemas" / "sub").mkdir(parents=True)
    (tmp_path / "schemas" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "schemas" / "sub" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    sibling = _write_path_schema(tmp_path / "schemas", "inc.xsd")
    assert validate_against("<patient>x</patient>", str(sibling)).valid
    nested = _write_path_schema(tmp_path / "schemas", "sub/inc.xsd")
    assert validate_against("<patient>x</patient>", str(nested)).valid
    assert validate_against("<patient>x</patient>", str(nested).encode()).valid


def _outside_include_under_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """schemas/main.xsd including ../outside.xsd, with the working directory at ``tmp_path``: a root
    that resolves to the working directory holds the include, while the schema's own directory does
    not."""
    (tmp_path / "outside.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path / "schemas", "../outside.xsd")
    monkeypatch.chdir(tmp_path)
    return main


@pytest.mark.parametrize("form", [".", "file:.", "schemas/..", "absolute"])
def test_a_relative_schema_root_resolves_against_the_working_directory(
    form: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A Handler may name a bundle relative to the engine's working directory, as xmlschema resolved
    # a relative schema before BACKLOG #5537; an earlier round of that fix refused the relative ones.
    main = _outside_include_under_cwd(tmp_path, monkeypatch)
    root = str(tmp_path) if form == "absolute" else form
    assert validate_against("<patient>x</patient>", str(main), schema_root=root).valid
    # Control: with no schema_root the include lies outside the schema's own directory.
    with pytest.raises(XmlValidationError, match="outside the schema's confinement root"):
        validate_against("<patient>x</patient>", str(main))


_WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="a drive-relative path is Windows text")


@_WINDOWS_ONLY
@pytest.mark.parametrize(
    ("form", "reason"),
    [
        # Each is the working directory when it is on that drive, and otherwise that drive's own
        # current directory; ea16ad7941 refused "file:" for the same widening and left these open.
        ("{d}", "a drive-relative path"),
        ("{d}.", "a drive-relative path"),
        ("{d}schemas\\..", "a drive-relative path"),
        ("file:///{d}", "a drive-relative path"),
        ("file:///{d}.", "a drive-relative path"),
        ("file:{d}", "a drive-relative path"),
        # The volume device; _local once returned the drive-relative "C:" for it.
        ("\\\\?\\{d}", "a UNC or device path"),
    ],
)
def test_a_drive_relative_schema_root_is_refused(
    form: str, reason: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = _outside_include_under_cwd(tmp_path, monkeypatch)
    root = form.format(d=tmp_path.drive)
    with pytest.raises(XmlValidationError, match=f"a schema_root that is {reason}"):
        validate_against("<patient>x</patient>", str(main), schema_root=root)


def test_relative_path_schema_resolves_its_include_beside_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    _write_path_schema(tmp_path / "schemas", "inc.xsd")
    monkeypatch.chdir(tmp_path)
    for source in ("schemas/main.xsd", "file:schemas/main.xsd", Path("schemas/main.xsd")):
        assert validate_against("<patient>x</patient>", source).valid, source


@_WINDOWS_ONLY
def test_a_drive_relative_schema_source_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = _write_path_schema(tmp_path / "schemas", "inc.xsd")
    (tmp_path / "schemas" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    d = tmp_path.drive
    for source in (
        f"{d}schemas\\main.xsd",
        f"file:///{d}schemas/main.xsd",
        f"file:{d}schemas/main.xsd",
    ):
        with pytest.raises(
            XmlValidationError, match="a schema location that is a drive-relative path"
        ):
            validate_against("<patient>x</patient>", source)
    # Control: the same file named absolutely loads, its include beside it.
    assert validate_against("<patient>x</patient>", str(main)).valid


@_WINDOWS_ONLY
def test_a_path_rooted_with_no_drive_takes_the_working_directorys_drive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # As xmlschema resolved one before BACKLOG #5537: "/x" is x on the working directory's drive.
    main = _outside_include_under_cwd(tmp_path, monkeypatch)
    rooted = main.as_posix()[len(tmp_path.drive) :]
    root = tmp_path.as_posix()[len(tmp_path.drive) :]
    assert validate_against("<patient>x</patient>", rooted, schema_root=root).valid
    assert validate_against("<patient>x</patient>", "file://" + rooted, schema_root=root).valid


def test_path_schema_nested_include_may_climb_back_inside_its_directory(tmp_path: Path) -> None:
    # main.xsd includes sub/inc.xsd, which includes ../common.xsd: still inside schemas/. xmlschema's
    # allow="sandbox" narrows to each includer's own directory and refused this.
    (tmp_path / "schemas" / "sub").mkdir(parents=True)
    (tmp_path / "schemas" / "common.xsd").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "schemas" / "sub" / "inc.xsd").write_text(
        f'<xs:schema {_XS}><xs:include schemaLocation="../common.xsd"/></xs:schema>',
        encoding="utf-8",
    )
    main = _write_path_schema(tmp_path / "schemas", "sub/inc.xsd")
    assert validate_against("<patient>x</patient>", str(main)).valid


def test_path_schema_may_be_a_file_url(tmp_path: Path) -> None:
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    assert validate_against("<patient>x</patient>", main.as_uri()).valid


def test_path_schema_include_of_a_prefix_sharing_sibling_is_refused(tmp_path: Path) -> None:
    # schemas-old/ shares the name prefix of schemas/; a string-prefix sandbox lets it through.
    (tmp_path / "schemas-old").mkdir()
    (tmp_path / "schemas-old" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path / "schemas", "../schemas-old/inc.xsd")
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)


def test_path_schema_remote_include_is_refused(tmp_path: Path) -> None:
    main = _write_path_schema(tmp_path, "http://127.0.0.1:9/x.xsd")
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "XMLResourceBlocked" in _causes(ei.value)


#: Well-known namespaces whose location-free import resolves to xmlschema's bundled copy.
_WELL_KNOWN = {
    "xmldsig": (
        "http://www.w3.org/2000/09/xmldsig#",
        '<xs:element name="patient"><xs:complexType><xs:sequence>'
        '<xs:element ref="w:Signature" minOccurs="0"/></xs:sequence></xs:complexType></xs:element>',
    ),
    "soap-encoding": (
        "http://schemas.xmlsoap.org/soap/encoding/",
        '<xs:element name="patient" type="w:string"/>',
    ),
}


@pytest.mark.parametrize("name", sorted(_WELL_KNOWN))
def test_location_free_import_of_a_well_known_namespace_still_resolves(
    name: str, tmp_path: Path
) -> None:
    ns, body = _WELL_KNOWN[name]
    schema = f'<xs:schema {_XS} xmlns:w="{ns}"><xs:import namespace="{ns}"/>{body}</xs:schema>'
    main = tmp_path / "main.xsd"
    main.write_text(schema, encoding="utf-8")
    for source in (schema, str(main)):
        assert validate_against("<patient/>", source).valid
        assert not validate_against("<other/>", source).valid


def test_path_schema_include_outside_its_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path / "schemas", "../outside/inc.xsd")
    # On origin/main allow="local" opened ../outside/inc.xsd: valid=True.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)


def test_path_schema_with_a_doctype_entity_is_refused(tmp_path: Path) -> None:
    main = tmp_path / "entity.xsd"
    main.write_text(_ENTITY, encoding="utf-8")
    # On origin/main the default defuse="remote" left a local file undefused: &nm; expanded, valid.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "XmlSecurityError" in _causes(ei.value)


def test_path_schema_with_an_empty_doctype_is_refused_like_inline_text(tmp_path: Path) -> None:
    # No entity at all, so xmlschema's own defusing passes it; parse_bytes refuses any DOCTYPE, and
    # the path route must not accept what the inline route refuses.
    text = f"<!DOCTYPE xs:schema []>{_CLEAN}"
    main = tmp_path / "empty-doctype.xsd"
    main.write_text(text, encoding="utf-8")
    for source in (text, str(main)):
        with pytest.raises(XmlValidationError) as ei:
            validate_against("<patient>x</patient>", source)
        assert "XmlSecurityError" in _causes(ei.value)


def test_path_schema_include_with_a_doctype_entity_is_refused(tmp_path: Path) -> None:
    (tmp_path / "inc.xsd").write_text(_ENTITY, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    with pytest.raises(XmlValidationError, match="a file that declares a DOCTYPE") as ei:
        validate_against("<patient>x</patient>", str(main))
    # parse_bytes refused it, not only xmlschema's narrower entity check.
    assert "XmlSecurityError" in _causes(ei.value)
    assert "inc.xsd" not in str(ei.value)  # PHI-safe: the location is not quoted


#: At least these os calls could touch a path for the validator. On Windows each opens a UNC path,
#: which is an SMB connection, so none may be handed one. Not every route is spied on: builtin open,
#: scandir and the os.path fast paths are not.
_TOUCHING = ("lstat", "stat", "readlink", "open")


def _spy_on_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    touched: list[str] = []

    def wrap(fn: Any) -> Any:
        def spy(path: Any, *args: Any, **kwargs: Any) -> Any:
            if isinstance(path, (str, bytes, os.PathLike)):
                touched.append(os.fsdecode(path))
            return fn(path, *args, **kwargs)

        return spy

    for name in _TOUCHING:
        monkeypatch.setattr(os, name, wrap(getattr(os, name)))
    monkeypatch.setattr(os.path, "realpath", wrap(os.path.realpath))
    return touched


@pytest.mark.parametrize(
    "location",
    [
        pytest.param("\\\\nonexist-5537.invalid\\share\\x.xsd", id="unc-backslash"),
        pytest.param("file:////nonexist-5537.invalid/share/x.xsd", id="unc-file-url"),
        pytest.param("\\\\?\\UNC\\nonexist-5537.invalid\\share\\x.xsd", id="unc-long"),
        pytest.param("\\\\.\\pipe\\nonexist-5537", id="device"),
    ],
)
def test_a_network_or_device_location_is_refused_before_anything_touches_it(
    location: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = _write_path_schema(tmp_path / "bad", location)
    (tmp_path / "good" / "inc-5537.xsd").parent.mkdir()
    (tmp_path / "good" / "inc-5537.xsd").write_text(_CLEAN, encoding="utf-8")
    control = _write_path_schema(tmp_path / "good", "inc-5537.xsd")
    touched = _spy_on_paths(monkeypatch)
    # Positive control: the spy does see the walk and the open of a local include.
    assert validate_against("<patient>x</patient>", str(control)).valid
    assert [p for p in touched if p.endswith("inc-5537.xsd")]
    for source in (main.read_text(encoding="utf-8"), str(main)):
        touched.clear()
        with pytest.raises(XmlValidationError) as ei:
            validate_against("<patient>x</patient>", source)
        assert "_ResourceRefused" in _causes(ei.value)
        assert not [p for p in touched if "nonexist-5537" in p]


@pytest.mark.parametrize("host", ["nonexist-5537.invalid", "localhost", "own-name"])
def test_a_file_url_path_naming_a_host_is_refused_on_its_text(
    host: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``schema._url_path`` says why each host form here was read, skipped or refused before; the
    remote one is why the test above went green on Windows and red on POSIX."""
    import ntpath
    import socket

    name = socket.gethostname() if host == "own-name" else host
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    # Rooted with no drive: on Windows it takes the working directory's drive, so stand there.
    monkeypatch.chdir(tmp_path)
    location = f"file:////{name}{ntpath.splitdrive((tmp_path / 'inc.xsd').as_posix())[1]}"
    main = _write_path_schema(tmp_path, location)
    # The path form first: for localhost it read the include before, and an inline schema did not.
    for source in (str(main), main.read_text(encoding="utf-8")):
        with pytest.raises(XmlValidationError, match="not a local file path") as ei:
            validate_against("<patient>x</patient>", source)
        assert "_ResourceRefused" in _causes(ei.value)
    # The same URL named as the schema itself is refused on its text with a fixed reason.
    with pytest.raises(XmlValidationError, match="a schema location that is a UNC or device path"):
        validate_against("<patient>x</patient>", location)


# --- a mapped drive, a long path, and links (BACKLOG #5537 repair) ---------------------------------


def test_no_path_is_resolved_with_realpath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # On Windows realpath rewrites a mapped drive (Z:) to the UNC path behind it, contacting the SMB
    # server to learn it, and a long path to its \\?\ form; either output was then refused as a UNC or
    # device path. Simulate the mapped drive: if anything still resolves through realpath, it gets UNC.
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "sub/inc.xsd")

    def as_if_mapped(path: Any, *args: Any, **kwargs: Any) -> str:
        return "\\\\fileserver-5537.invalid\\share\\" + os.path.basename(os.fsdecode(path))

    monkeypatch.setattr(os.path, "realpath", as_if_mapped)
    assert validate_against("<patient>x</patient>", str(main)).valid
    assert validate_against("<patient>x</patient>", str(main), schema_root=tmp_path).valid


@pytest.mark.skipif(os.name != "nt", reason="the \\\\?\\ long-path prefix is Windows syntax")
def test_a_long_path_prefix_on_a_drive_letter_is_a_local_path(tmp_path: Path) -> None:
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    assert validate_against("<patient>x</patient>", "\\\\?\\" + str(main)).valid
    # The same prefix on an include, which xmlschema hands the opener as file:////%3F/C%3A/...,
    # and on the schema itself as a file URL.
    long_inc = _write_path_schema(tmp_path / "sub", "\\\\?\\" + str(tmp_path / "inc.xsd"))
    assert validate_against("<patient>x</patient>", str(long_inc), schema_root=tmp_path).valid
    assert validate_against("<patient>x</patient>", "file:////%3F/" + main.as_posix()).valid


@pytest.mark.skipif(os.name != "nt", reason="a drive letter is Windows path text")
def test_a_file_url_with_a_drive_in_the_authority_position_is_a_local_path(tmp_path: Path) -> None:
    # As a source or a schema_root, file:////C:/... loaded before BACKLOG #5537, and was then
    # refused as a UNC path (\\C:\...). On an include, xmlschema refuses it as an invalid URI
    # before the opener sees it.
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    assert validate_against("<patient>x</patient>", "file:////" + main.as_posix()).valid
    assert validate_against(
        "<patient>x</patient>", str(main), schema_root="file:////" + tmp_path.as_posix()
    ).valid


def test_only_a_windows_drive_authority_goes_to_url2pathname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``schema._url_path``'s classification, measured on every platform: on Windows an authority
    whose second character is ``:`` is a drive and goes to ``url2pathname``; a host is kept as
    written, and so is a drive on POSIX."""
    from messagefoundry.parsing.xml.schema import _local, _url_path

    def spy(path: str) -> str:
        return f"url2pathname({path})"

    for name in ("nt", "posix"):
        with monkeypatch.context() as m:
            m.setattr(urllib.request, "url2pathname", spy)
            m.setattr(os, "name", name)
            drive = _url_path("//C:/schemas/main.xsd")
            host = _url_path("//server/share/x.xsd")
            empty = _url_path("/C:/schemas/main.xsd")
        assert (drive == "url2pathname(//C:/schemas/main.xsd)") is (name == "nt"), (name, drive)
        assert host == f"{os.sep}{os.sep}server{os.sep}share{os.sep}x.xsd", (name, host)
        assert empty == "url2pathname(/C:/schemas/main.xsd)", (name, empty)
    if os.name != "nt":  # kept as written, a drive authority is a UNC path here, and is refused
        assert _local(_url_path("//C:/schemas/main.xsd")) is None


@pytest.mark.skipif(os.name != "nt", reason="drive and UNC syntax is Windows path text")
@pytest.mark.parametrize(
    ("written", "local"),
    [
        ("C:\\s\\x.xsd", "C:\\s\\x.xsd"),
        ("\\\\?\\C:\\s\\..\\x.xsd", "C:\\x.xsd"),
        ("//?/C:/s/x.xsd", "C:\\s\\x.xsd"),
        ("\\\\host\\share\\x.xsd", None),
        ("//host/share/x.xsd", None),
        ("\\\\?\\UNC\\host\\share\\x.xsd", None),
        ("\\\\.\\C:\\x.xsd", None),
        ("\\\\?\\C:", None),  # the volume device; _local returned the drive-relative "C:"
        ("\\\\.\\pipe\\x", None),
        ("\\\\?\\GLOBALROOT\\Device\\x", None),
    ],
)
def test_local_judges_the_written_text(written: str, local: str | None) -> None:
    from messagefoundry.parsing.xml.schema import _local

    assert _local(written) == local


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # Windows without Developer Mode or the privilege
        pytest.skip(f"cannot create a symlink here: {type(exc).__name__}")


def _junction_or_skip(target: Path, link: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("a junction is a Windows mount point")
    import _winapi  # CPython's own junction maker; needs no privilege, unlike a symlink

    _winapi.CreateJunction(str(target), str(link))


@pytest.mark.parametrize(
    "make_link", [_symlink_or_skip, _junction_or_skip], ids=["symlink", "junction"]
)
def test_a_link_out_of_the_root_is_refused(tmp_path: Path, make_link: Any) -> None:
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "schemas" / "inside").mkdir(parents=True)
    (tmp_path / "schemas" / "inside" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    make_link(tmp_path / "outside", tmp_path / "schemas" / "out")
    make_link(tmp_path / "schemas" / "inside", tmp_path / "schemas" / "in")
    main = _write_path_schema(tmp_path / "schemas", "out/inc.xsd")
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)
    # Control: a link that stays inside the root is followed.
    main = _write_path_schema(tmp_path / "schemas", "in/inc.xsd")
    assert validate_against("<patient>x</patient>", str(main)).valid


def test_a_link_to_a_unc_share_is_refused_before_it_is_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Runs everywhere: lstat reports lnk/ as a link and readlink names a share. lnk/ is really a
    # directory holding inc.xsd, so following the link instead of judging it would validate.
    (tmp_path / "lnk").mkdir()
    (tmp_path / "lnk" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "lnk/inc.xsd")
    assert validate_against("<patient>x</patient>", str(main)).valid  # control, before the fake
    link = os.path.normcase(str(tmp_path / "lnk"))
    real_lstat, real_readlink = os.lstat, os.readlink

    def fake_lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.path.normcase(os.fsdecode(path)) == link:
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return real_lstat(path, *args, **kwargs)

    def fake_readlink(path: Any, *args: Any, **kwargs: Any) -> str:
        if os.path.normcase(os.fsdecode(path)) == link:
            return "//nonexist-5537.invalid/share"
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "readlink", fake_readlink)
    touched = _spy_on_paths(monkeypatch)
    with pytest.raises(
        XmlValidationError, match="a link that leads out of the root, to a UNC"
    ) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)
    assert not [p for p in touched if "nonexist-5537" in p]


def test_a_schema_file_that_is_a_link_is_read_and_resolves_includes_beside_the_link(
    tmp_path: Path,
) -> None:
    # The file the caller names is read through a link at it, and its includes resolve beside the
    # name as written, as xmlschema resolved them before BACKLOG #5537. A lexical reading of a link's
    # relative target can name a different file than the OS opens, so the named file is not resolved.
    (tmp_path / "real").mkdir()
    target = _write_path_schema(tmp_path / "real", "inc.xsd")
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    _symlink_or_skip(target, tmp_path / "cfg" / "main.xsd")
    assert validate_against("<patient>x</patient>", str(tmp_path / "cfg" / "main.xsd")).valid


def test_an_unreadable_link_under_the_root_fails_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # xmlschema drops an include that raises OSError with only a warning, so a refusal surfacing as
    # one would load the schema without the include. It must fail the build, like a link out.
    (tmp_path / "lnk").mkdir()
    (tmp_path / "lnk" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "lnk/inc.xsd")
    link = os.path.normcase(str(tmp_path / "lnk"))
    real_lstat, real_readlink = os.lstat, os.readlink

    def fake_lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.path.normcase(os.fsdecode(path)) == link:
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return real_lstat(path, *args, **kwargs)

    def fake_readlink(path: Any, *args: Any, **kwargs: Any) -> str:
        if os.path.normcase(os.fsdecode(path)) == link:
            raise OSError("not a link this platform can read")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "readlink", fake_readlink)
    with pytest.raises(XmlValidationError, match="a location that cannot be read as a file") as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)


def test_an_import_with_a_doctype_falls_back_to_the_bundled_copy(tmp_path: Path) -> None:
    # The stock W3C xmldsig-core-schema.xsd carries a DOCTYPE, and SAML and WS-Security bundles import
    # it by a local schemaLocation. The opener refuses that file as blocked, so xmlschema falls back to
    # its bundled copy, as it does with defuse="always" alone, instead of failing the whole build.
    ns = "http://www.w3.org/2000/09/xmldsig#"
    (tmp_path / "xmldsig.xsd").write_text(
        '<?xml version="1.0"?><!DOCTYPE schema [<!ENTITY x "y">]>'
        f'<xs:schema {_XS} targetNamespace="{ns}"/>',
        encoding="utf-8",
    )
    main = tmp_path / "main.xsd"
    main.write_text(
        f'<xs:schema {_XS} xmlns:w="{ns}">'
        f'<xs:import namespace="{ns}" schemaLocation="xmldsig.xsd"/>'
        '<xs:element name="patient"><xs:complexType><xs:sequence>'
        '<xs:element ref="w:Signature" minOccurs="0"/></xs:sequence></xs:complexType></xs:element>'
        "</xs:schema>",
        encoding="utf-8",
    )
    assert validate_against("<patient/>", str(main)).valid
    assert not validate_against("<other/>", str(main)).valid


#: Imports urn:o, which no bundled copy covers, and admits its content through a LAX wildcard. Loaded,
#: urn:o types o:id as an integer, so the instance below is invalid; with the import skipped, a lax
#: wildcard admits the unknown element unchecked and the same instance validates.
_LAX_IMPORTER = (
    f'<xs:schema {_XS}><xs:import namespace="urn:o" schemaLocation="{{location}}"/>'
    '<xs:element name="patient"><xs:complexType><xs:sequence>'
    '<xs:any namespace="urn:o" processContents="lax"/>'
    "</xs:sequence></xs:complexType></xs:element></xs:schema>"
)
_URN_O = (
    f'<xs:schema {_XS} targetNamespace="urn:o"><xs:element name="id" type="xs:int"/></xs:schema>'
)
_URN_O_DOCTYPE = '<?xml version="1.0"?><!DOCTYPE xs:schema [<!ENTITY x "y">]>' + _URN_O
_LAX_INSTANCE = '<patient><o:id xmlns:o="urn:o">x</o:id></patient>'


def _lax_import_outcome(schema: str) -> str:
    """``build-fails``, ``valid`` or ``invalid`` for :data:`_LAX_INSTANCE` against ``schema``."""
    try:
        result = validate_against(_LAX_INSTANCE, schema)
    except XmlValidationError:
        return "build-fails"
    return "valid" if result.valid else "invalid"


@pytest.mark.parametrize(
    "imported",
    [
        pytest.param("<xs:schema", id="malformed"),
        pytest.param(_URN_O_DOCTYPE, id="doctype"),
        pytest.param("", id="empty"),
    ],
)
def test_a_refused_import_with_no_bundled_copy_fails_the_build(
    imported: str, tmp_path: Path
) -> None:
    # On 12e253ecb7 the opener raised XMLResourceBlocked for these, xmlschema skipped the import with
    # only a warning, and the lax wildcard admitted o:id unchecked: valid=True. origin/main failed the
    # build on a malformed file, and read a DOCTYPE one and found o:id invalid.
    (tmp_path / "o.xsd").write_text(imported, encoding="utf-8")
    main = tmp_path / "main.xsd"
    main.write_text(_LAX_IMPORTER.format(location="o.xsd"), encoding="utf-8")
    assert _lax_import_outcome(str(main)) == "build-fails"
    # Control: the same import of a sound urn:o loads it, and o:id is checked.
    (tmp_path / "o.xsd").write_text(_URN_O, encoding="utf-8")
    assert _lax_import_outcome(str(main)) == "invalid"


@pytest.mark.parametrize(
    "make_link", [_symlink_or_skip, _junction_or_skip], ids=["symlink", "junction"]
)
def test_an_import_through_a_link_out_fails_the_build(tmp_path: Path, make_link: Any) -> None:
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "o.xsd").write_text(_URN_O, encoding="utf-8")
    (tmp_path / "schemas").mkdir()
    make_link(tmp_path / "outside", tmp_path / "schemas" / "out")
    main = tmp_path / "schemas" / "main.xsd"
    main.write_text(_LAX_IMPORTER.format(location="out/o.xsd"), encoding="utf-8")
    assert _lax_import_outcome(str(main)) == "build-fails"


def test_an_import_outside_the_root_fails_the_build(tmp_path: Path) -> None:
    (tmp_path / "o.xsd").write_text(_URN_O, encoding="utf-8")
    (tmp_path / "schemas").mkdir()
    main = tmp_path / "schemas" / "main.xsd"
    main.write_text(_LAX_IMPORTER.format(location="../o.xsd"), encoding="utf-8")
    assert _lax_import_outcome(str(main)) == "build-fails"
    # An inline schema has no root, so its local import is refused the same way.
    inline = _LAX_IMPORTER.format(location=(tmp_path / "o.xsd").as_uri())
    assert _lax_import_outcome(inline) == "build-fails"


def test_a_nested_include_refused_under_an_import_fails_the_build(tmp_path: Path) -> None:
    (tmp_path / "o.xsd").write_text(
        f'<xs:schema {_XS} targetNamespace="urn:o"><xs:include schemaLocation="bad.xsd"/></xs:schema>',
        encoding="utf-8",
    )
    (tmp_path / "bad.xsd").write_text(_URN_O_DOCTYPE, encoding="utf-8")
    main = tmp_path / "main.xsd"
    main.write_text(_LAX_IMPORTER.format(location="o.xsd"), encoding="utf-8")
    assert _lax_import_outcome(str(main)) == "build-fails"


_DSIG = "http://www.w3.org/2000/09/xmldsig#"


@pytest.mark.parametrize(
    "inner",
    [
        pytest.param('<xs:include schemaLocation="bad.xsd"/>', id="include-doctype"),
        pytest.param('<xs:import namespace="urn:o" schemaLocation="../o.xsd"/>', id="import-out"),
    ],
)
def test_a_refusal_inside_an_opened_bundled_namespace_import_fails_the_build(
    inner: str, tmp_path: Path
) -> None:
    # Only the import's OWN location falls back to the bundled copy. ds.xsd opens cleanly, so a
    # refusal inside it is not that location: falling back there left ds.xsd half registered, and in
    # the import-out shape its lax wildcard admitted o:id unchecked, valid=True.
    (tmp_path / "o.xsd").write_text(_URN_O, encoding="utf-8")
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "bad.xsd").write_text(
        '<?xml version="1.0"?><!DOCTYPE xs:schema [<!ENTITY x "y">]>'
        f'<xs:schema {_XS} targetNamespace="{_DSIG}"/>',
        encoding="utf-8",
    )
    (tmp_path / "schemas" / "ds.xsd").write_text(
        f'<xs:schema {_XS} targetNamespace="{_DSIG}">{inner}'
        '<xs:element name="Holder"><xs:complexType><xs:sequence>'
        '<xs:any namespace="urn:o" processContents="lax"/>'
        "</xs:sequence></xs:complexType></xs:element></xs:schema>",
        encoding="utf-8",
    )
    main = tmp_path / "schemas" / "main.xsd"
    main.write_text(
        f'<xs:schema {_XS} xmlns:w="{_DSIG}">'
        f'<xs:import namespace="{_DSIG}" schemaLocation="ds.xsd"/>'
        '<xs:element name="patient"><xs:complexType><xs:sequence>'
        '<xs:element ref="w:Holder"/></xs:sequence></xs:complexType></xs:element></xs:schema>',
        encoding="utf-8",
    )
    doc = (
        f'<patient><w:Holder xmlns:w="{_DSIG}"><o:id xmlns:o="urn:o">x</o:id></w:Holder></patient>'
    )
    with pytest.raises(XmlValidationError) as ei:
        validate_against(doc, str(main))
    assert "_ResourceRefused" in _causes(ei.value)


def test_a_refusal_names_its_fixed_reason(tmp_path: Path) -> None:
    (tmp_path / "o.xsd").write_text(_URN_O, encoding="utf-8")
    main = _write_path_schema(tmp_path / "schemas", "../o.xsd")
    with pytest.raises(XmlValidationError, match="outside the schema's confinement root") as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "o.xsd" not in str(ei.value)  # PHI-safe: the location is not quoted


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        # Reading a directory raises an OSError (PermissionError from the open on Windows; elsewhere
        # the fstat check refuses it before any read), and a NUL in the path a ValueError. Both used
        # to fail the build as "a link out, or a file parse_bytes refuses", neither of which happened.
        pytest.param("dir5537.xsd", "a location that cannot be read as a file", id="directory"),
        pytest.param("dir5537%00.xsd", "a location that cannot be read as a file", id="nul-byte"),
        # abspath maps a reserved device name to a device path, which used to read as outside the
        # root.
        pytest.param(
            "nul",
            "a resource that is not a local file path",
            id="device-name",
            marks=pytest.mark.skipif(os.name != "nt", reason="a reserved device name is Windows"),
        ),
    ],
)
def test_a_refused_include_names_a_true_reason(location: str, reason: str, tmp_path: Path) -> None:
    (tmp_path / "dir5537.xsd").mkdir()
    main = _write_path_schema(tmp_path, location)
    with pytest.raises(XmlValidationError, match=reason) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "dir5537" not in str(ei.value)  # PHI-safe: the location is not quoted


def _open_fds() -> int | None:
    """How many descriptors this process holds, or ``None`` where no listing exists (Windows)."""
    for listing in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(listing):
            return len(os.listdir(listing))
    return None


def test_a_directory_location_is_refused_and_leaks_no_descriptor(tmp_path: Path) -> None:
    # On POSIX os.open succeeds on a directory and os.fdopen then raised IsADirectoryError without
    # closing the descriptor, so every build that met one leaked it. Windows refuses the open itself.
    (tmp_path / "dir5537.xsd").mkdir()
    main = _write_path_schema(tmp_path, "dir5537.xsd")

    def refuse_both() -> None:
        with pytest.raises(XmlValidationError, match="a location that cannot be read as a file"):
            validate_against("<patient>x</patient>", str(main))
        # The named schema itself being a directory takes the same read, and fails the build.
        with pytest.raises(XmlValidationError, match="could not load XSD schema"):
            validate_against("<patient>x</patient>", str(tmp_path / "dir5537.xsd"))

    refuse_both()  # warm-up, so anything opened once and kept is not counted
    gc.collect()  # so a collection mid-loop cannot close an earlier test's descriptor and mask one
    before = _open_fds()
    if before is None:  # Windows: no listing to count, and the refusal is asserted above
        return
    for _ in range(5):
        refuse_both()
    after = _open_fds()
    assert after is not None
    assert after <= before  # 10 refusals, so a leak shows as 10 more descriptors


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a FIFO is POSIX")
@pytest.mark.timeout(60)
def test_a_fifo_location_is_refused_without_blocking(tmp_path: Path) -> None:
    # With no O_NONBLOCK the open waited for a writer that never comes, and the build hung.
    os.mkfifo(tmp_path / "fifo5537.xsd")
    main = _write_path_schema(tmp_path, "fifo5537.xsd")
    with pytest.raises(XmlValidationError, match="a location that cannot be read as a file") as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "fifo5537" not in str(ei.value)  # PHI-safe: the location is not quoted


def test_a_path_that_runs_on_through_a_file_is_refused(tmp_path: Path) -> None:
    # POSIX refused this as NotADirectoryError, while Windows reported it missing and xmlschema skipped
    # the include with a warning, so the schema loaded without it. Both refuse it now.
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    for location in ("inc.xsd/b.xsd", "inc.xsd/sub/b.xsd"):
        main = _write_path_schema(tmp_path / "schemas", f"../{location}")
        with pytest.raises(XmlValidationError, match="a location that cannot be read as a file"):
            validate_against("<patient>x</patient>", str(main), schema_root=str(tmp_path))
    # Control: a missing file under a real directory is still skipped, as xmlschema always did.
    main = _write_path_schema(tmp_path / "schemas", "../absent/b.xsd")
    with pytest.warns(Warning, match="Include schema failed"):
        assert not validate_against(
            "<patient>x</patient>", str(main), schema_root=str(tmp_path)
        ).valid


def test_a_root_that_is_a_file_refuses_a_path_below_it(tmp_path: Path) -> None:
    # A schema at a filesystem root is confined to itself, a file; nothing lies below it.
    from messagefoundry.parsing.xml.schema import _resolve_within

    root = tmp_path / "top.xsd"
    root.write_text(_CLEAN, encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        _resolve_within(str(root / "b.xsd"), str(root))
    assert _resolve_within(str(root), str(root)) == str(root)  # control: the file itself


def test_a_path_through_a_bundled_file_is_refused() -> None:
    # The bundled root is read without the walk, so it takes its own check on Windows.
    through = _bundled_directory() / "xmldsig-core-schema.xsd" / "x.xsd"
    schema = f'<xs:schema {_XS}><xs:include schemaLocation="{through.as_uri()}"/></xs:schema>'
    with pytest.raises(XmlValidationError, match="a location that cannot be read as a file"):
        validate_against("<patient>x</patient>", schema)


def test_bytearray_inline_schema_is_read_as_the_schema() -> None:
    # origin/main pre-parsed a bytearray schema as text; 12e253ecb7 sent it to the path branch, where
    # os.fsdecode refused it and the schema failed to load.
    assert validate_against("<patient>x</patient>", bytearray(_CLEAN.encode("utf-8"))).valid
    assert not validate_against("<other>x</other>", bytearray(_CLEAN.encode("utf-8"))).valid
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", bytearray(_ENTITY.encode("utf-8")))
    assert "XmlSecurityError" in _causes(ei.value)


def test_a_percent_sequence_in_a_directory_name_is_decoded_once(tmp_path: Path) -> None:
    (tmp_path / "v100%41").mkdir()
    (tmp_path / "v100%41" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path / "v100%41", "inc.xsd")
    for source in (str(main), main.as_uri()):
        assert validate_against("<patient>x</patient>", source).valid


def test_a_circular_include_back_to_the_named_file_loads(tmp_path: Path) -> None:
    # XSD allows it, and xmlschema skips a document it already holds by URL. Handed a tree with no URL
    # it loaded the named file a second time and failed on duplicate globals.
    main = tmp_path / "main.xsd"
    main.write_text(
        f'<xs:schema {_XS}><xs:include schemaLocation="a.xsd"/>'
        '<xs:element name="patient" type="xs:string"/></xs:schema>',
        encoding="utf-8",
    )
    (tmp_path / "a.xsd").write_text(
        f'<xs:schema {_XS}><xs:include schemaLocation="main.xsd"/></xs:schema>', encoding="utf-8"
    )
    assert validate_against("<patient>x</patient>", str(main)).valid


#: Loads only if the DOCTYPE inside the location text takes effect: its ATTLIST default types the
#: element as an integer, so "5" validates and "x" does not.
_TEXT_LOCATION = (
    "&#10;&lt;!DOCTYPE xs:schema [&lt;!ATTLIST xs:element type CDATA 'xs:int'&gt;]&gt;"
    "&lt;xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'&gt;"
    "&lt;xs:element name='patient'/&gt;&lt;/xs:schema&gt;"
)


def test_a_location_xmlschema_would_parse_as_text_is_refused(tmp_path: Path) -> None:
    # xmlschema reads a location holding a newline, or opening with "<", as an inline document,
    # which never reaches the opener or parse_bytes.
    inline = f'<xs:schema {_XS}><xs:include schemaLocation="{_TEXT_LOCATION}"/></xs:schema>'
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>5</patient>", inline)
    assert "XmlSecurityError" in _causes(ei.value)
    (tmp_path / "inc.xsd").write_text(inline, encoding="utf-8")
    included = _write_path_schema(tmp_path, "inc.xsd")
    named = tmp_path / "named.xsd"
    named.write_text(inline, encoding="utf-8")
    for source in (included, named):
        with pytest.raises(XmlValidationError):
            validate_against("<patient>5</patient>", str(source))
    # Control: an ordinary location in the same position still loads.
    (tmp_path / "inc2.xsd").write_text(_CLEAN, encoding="utf-8")
    control = _write_path_schema(tmp_path, "inc2.xsd")
    assert validate_against("<patient>x</patient>", str(control)).valid


def test_a_reparse_point_readlink_rejects_fails_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows os.readlink raises ValueError, not OSError, for a name surrogate it cannot read,
    # such as a WSL symlink.
    (tmp_path / "lnk").mkdir()
    (tmp_path / "lnk" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "lnk/inc.xsd")
    link = os.path.normcase(str(tmp_path / "lnk"))
    real_lstat, real_readlink = os.lstat, os.readlink

    def fake_lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.path.normcase(os.fsdecode(path)) == link:
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return real_lstat(path, *args, **kwargs)

    def fake_readlink(path: Any, *args: Any, **kwargs: Any) -> str:
        if os.path.normcase(os.fsdecode(path)) == link:
            raise ValueError("not a symbolic link")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "readlink", fake_readlink)
    with pytest.raises(XmlValidationError, match="a location that cannot be read as a file") as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)


def test_a_path_object_schema_source_is_a_path(tmp_path: Path) -> None:
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    assert validate_against("<patient>x</patient>", main, schema_root=tmp_path).valid


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH and the \\\\?\\ prefix are Windows")
def test_a_long_drive_path_gets_its_prefix_back_for_the_os(tmp_path: Path) -> None:
    from messagefoundry.parsing.xml.schema import _native

    long = "C:\\" + "d\\" * 140 + "main.xsd"
    assert _native(long) == "\\\\?\\" + long
    assert _native("C:\\s\\main.xsd") == "C:\\s\\main.xsd"
    # A real one, past MAX_PATH, read through validate_against.
    deep = tmp_path.joinpath(*(["d" * 40] * 6))
    try:
        deep.mkdir(parents=True)
        (deep / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    except OSError as exc:
        pytest.skip(f"cannot create a long path here: {type(exc).__name__}")
    main = _write_path_schema(deep, "inc.xsd")
    assert len(str(main)) > 260
    assert validate_against("<patient>x</patient>", str(main)).valid


# --- schema_root: a bundle that includes across sibling directories ------------------------------


def _write_cda_shaped_bundle(top: Path) -> Path:
    """The HL7 CDA R2 layout: the entry schema includes ``../../processable/coreschemas/...``."""
    (top / "infrastructure" / "cda").mkdir(parents=True)
    (top / "processable" / "coreschemas").mkdir(parents=True)
    (top / "processable" / "coreschemas" / "datatypes.xsd").write_text(_CLEAN, encoding="utf-8")
    return _write_path_schema(
        top / "infrastructure" / "cda", "../../processable/coreschemas/datatypes.xsd"
    )


def test_a_cda_shaped_bundle_needs_schema_root(tmp_path: Path) -> None:
    main = _write_cda_shaped_bundle(tmp_path / "cda")
    # Confined to its own directory, the cross-directory include is refused.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    assert "_ResourceRefused" in _causes(ei.value)
    for root in (tmp_path / "cda", str(tmp_path / "cda"), (tmp_path / "cda").as_uri()):
        assert validate_against("<patient>x</patient>", str(main), schema_root=root).valid
        assert not validate_against("<other>x</other>", str(main), schema_root=root).valid


def test_schema_root_still_vets_each_file_under_it(tmp_path: Path) -> None:
    main = _write_cda_shaped_bundle(tmp_path / "cda")
    (tmp_path / "cda" / "processable" / "coreschemas" / "datatypes.xsd").write_text(
        _ENTITY, encoding="utf-8"
    )
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main), schema_root=tmp_path / "cda")
    assert "XmlSecurityError" in _causes(ei.value)


def test_an_include_climbing_above_schema_root_is_refused(tmp_path: Path) -> None:
    main = _write_cda_shaped_bundle(tmp_path / "cda")
    # The include reaches cda/processable/, one level above the root named here.
    with pytest.raises(XmlValidationError) as ei:
        validate_against(
            "<patient>x</patient>", str(main), schema_root=tmp_path / "cda" / "infrastructure"
        )
    assert "_ResourceRefused" in _causes(ei.value)


def test_schema_root_must_hold_the_schema(tmp_path: Path) -> None:
    main = _write_cda_shaped_bundle(tmp_path / "cda")
    (tmp_path / "elsewhere").mkdir()
    with pytest.raises(XmlValidationError, match="does not lie under schema_root"):
        validate_against("<patient>x</patient>", str(main), schema_root=tmp_path / "elsewhere")


def test_schema_root_is_refused_for_an_inline_schema(tmp_path: Path) -> None:
    with pytest.raises(XmlValidationError, match="inline schema"):
        validate_against("<patient>x</patient>", _CLEAN, schema_root=tmp_path)


@pytest.mark.parametrize("url", ["file:", "file://", "file://localhost", "file:///"])
def test_a_file_url_naming_no_path_is_refused(url: str, tmp_path: Path) -> None:
    # url2pathname gives "" (or "/"). abspath("") is the working directory, which such a URL does
    # not name ("file:." does), and "/" is a filesystem root.
    main = _write_path_schema(tmp_path, "inc.xsd")
    with pytest.raises(XmlValidationError, match="naming no path|filesystem root"):
        validate_against("<patient>x</patient>", str(main), schema_root=url)
    with pytest.raises(XmlValidationError):
        validate_against("<patient>x</patient>", url)


def test_a_refusal_while_validating_is_a_schema_load_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With no bundled root (xmlschema installed on a UNC path), a lax ##other wildcard meeting an
    # xlink element makes xmlschema load the bundled xlink.xsd during iter_errors, and the opener
    # refuses it. That refusal escaped validate_against as the private _ResourceRefused.
    from messagefoundry.parsing.xml import schema as schema_mod

    monkeypatch.setattr(schema_mod, "_bundled_root", lambda module_file: ())
    schema = (
        f'<xs:schema {_XS} targetNamespace="urn:t"><xs:element name="e"><xs:complexType>'
        '<xs:sequence><xs:any namespace="##other" processContents="lax"/></xs:sequence>'
        "</xs:complexType></xs:element></xs:schema>"
    )
    doc = '<t:e xmlns:t="urn:t"><l:simple xmlns:l="http://www.w3.org/1999/xlink"/></t:e>'
    with pytest.raises(XmlValidationError) as ei:
        validate_against(doc, schema)
    assert "_ResourceRefused" in _causes(ei.value)


@pytest.mark.parametrize("root", ["", "   "])
def test_an_empty_schema_root_is_refused(root: str, tmp_path: Path) -> None:
    # abspath("") is the working directory, which an empty value does not name ("." does).
    main = _write_path_schema(tmp_path, "inc.xsd")
    with pytest.raises(XmlValidationError, match="empty"):
        validate_against("<patient>x</patient>", str(main), schema_root=root)


def test_a_unc_schema_root_is_refused(tmp_path: Path) -> None:
    main = _write_path_schema(tmp_path, "inc.xsd")
    with pytest.raises(XmlValidationError, match="UNC or device"):
        validate_against("<patient>x</patient>", str(main), schema_root="//nonexist-5537.invalid/s")


def test_a_filesystem_root_schema_root_is_refused(tmp_path: Path) -> None:
    # It would make every file on the volume readable, the widening a schema at a root is denied.
    main = _write_path_schema(tmp_path, "inc.xsd")
    with pytest.raises(XmlValidationError, match="a schema_root that is a filesystem root"):
        validate_against("<patient>x</patient>", str(main), schema_root=tmp_path.anchor)


def test_a_schema_at_a_filesystem_root_is_confined_to_itself(tmp_path: Path) -> None:
    from messagefoundry.parsing.xml.schema import _confinement_root

    top = os.path.abspath(tmp_path.anchor)
    at_top = os.path.join(top, "main.xsd")
    assert _confinement_root(at_top, None).path == at_top
    # Control: one level down, the directory is the root.
    nested = os.path.join(top, "d", "main.xsd")
    assert _confinement_root(nested, None).path == os.path.join(top, "d")


def test_only_the_exact_named_file_skips_the_link_walk(tmp_path: Path) -> None:
    # The named file may be a link out of its directory and is read as named. A name differing from it
    # only in case is another file in a case-sensitive Windows directory, so it takes the walk; it used
    # to match on normcase and be read through the link unwalked.
    from messagefoundry.parsing.xml.schema import (
        _ConfinedFiles,
        _ConfinedOpener,
        _ResourceRefused,
        _Root,
    )

    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "main.xsd").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "cfg").mkdir()
    entry = tmp_path / "cfg" / "main.xsd"
    _symlink_or_skip(tmp_path / "real" / "main.xsd", entry)
    opener = _ConfinedOpener(_ConfinedFiles((_Root(str(tmp_path / "cfg"), vet=True),), str(entry)))
    assert b"patient" in opener.open(entry.as_uri()).read()  # control: the named file itself
    variant = (tmp_path / "cfg" / "MAIN.xsd").as_uri()
    # Case-insensitive here: the walk finds the link and refuses its target. Case-sensitive: no file.
    with pytest.raises((_ResourceRefused, FileNotFoundError)):
        opener.open(variant)


def test_a_non_file_url_reaching_the_opener_is_a_refused_resource() -> None:
    from messagefoundry.parsing.xml.schema import _ConfinedFiles, _ConfinedOpener, _ResourceRefused

    opener = _ConfinedOpener(_ConfinedFiles(()))
    for url in ("http://127.0.0.1:9/x.xsd", "https://127.0.0.1:9/x.xsd", "data:text/plain,x"):
        with pytest.raises(_ResourceRefused):
            opener.open(url)


@pytest.mark.parametrize(
    "source",
    ["http://127.0.0.1:9/x.xsd", "ftp://127.0.0.1:9/x.xsd", "urn:x-5537:schema"],
)
def test_a_non_file_schema_source_is_refused(source: str) -> None:
    # It used to become a path relative to the working directory, which xmlschema then opened.
    with pytest.raises(XmlValidationError, match="not a local path"):
        validate_against("<patient>x</patient>", source)


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "LocalHost"])
def test_a_file_url_naming_localhost_in_any_case_is_local(host: str, tmp_path: Path) -> None:
    (tmp_path / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    main = _write_path_schema(tmp_path, "inc.xsd")
    url = main.as_uri().replace("file://", f"file://{host}", 1)
    assert validate_against("<patient>x</patient>", url).valid
    # Control: any other host is refused.
    with pytest.raises(XmlValidationError, match="naming a host"):
        validate_against("<patient>x</patient>", url.replace(host, "example.invalid", 1))


@pytest.mark.parametrize("codec", ["utf-16-be", "utf-16-le"])
def test_bomless_utf16_schema_bytes_are_read_as_the_schema(codec: str) -> None:
    # With a declaration the parser detects the encoding from the first bytes and the schema loads.
    declared = ('<?xml version="1.0" encoding="UTF-16"?>' + _CLEAN).encode(codec)
    assert validate_against("<patient>x</patient>", declared).valid
    # Without one it still goes to the hardened parser, never to the filesystem as a path.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", _CLEAN.encode(codec))
    assert "XmlParseError" in _causes(ei.value)
    # Leading whitespace puts the "<" past the first four bytes; the NUL still marks it as text.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", ("  " + _CLEAN).encode(codec))
    assert "XmlParseError" in _causes(ei.value)


# --- limb 3: a document the hardened parser refuses is raised, as the docstring now says ---------


def test_malformed_document_raises_parse_error() -> None:
    with pytest.raises(XmlParseError):
        validate_against("<patient>", _CLEAN)


def test_doctype_document_raises_security_error() -> None:
    doc = '<?xml version="1.0"?><!DOCTYPE patient [<!ENTITY x "y">]><patient>&x;</patient>'
    with pytest.raises(XmlSecurityError):
        validate_against(doc, _CLEAN)


def test_docstring_names_both_document_errors() -> None:
    doc = validate_against.__doc__ or ""
    assert "XmlParseError" in doc and "XmlSecurityError" in doc
