# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``validate_against`` reads no resource beyond the schema it is given (BACKLOG #5537).

Three limbs, each pinned against the behaviour it replaces:

* a schema opening with a byte-order mark is the schema DOCUMENT, not a path, so it goes through the
  hardened pre-parse. A BOM-prefixed ``bytes`` schema used to skip that pre-parse, and xmlschema then
  expanded a DOCTYPE entity in it;
* every open goes through ``schema._ConfinedFiles``, xmlschema's opener: an inline schema opens none
  of its own locations, a path schema opens files only under its own directory, each checked by
  ``parse_bytes``, and either may read xmlschema's bundled copies of well-known namespaces.
  ``allow="local"`` still refuses a remote URL before the opener sees it;
* a malformed or DOCTYPE ``document`` raises the hardened parser's error rather than returning an
  invalid result, and the docstring now says so.

Every file a test writes is under ``tmp_path``; nothing depends on the process's working directory
except the one test that sets it with ``monkeypatch.chdir``.
"""

from __future__ import annotations

import codecs
import os
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
    assert "XMLResourceBlocked" in _causes(ei.value)
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
    # A refused import is skipped with a warning, so the type it would have defined is unknown and
    # the build fails. On origin/main the import read other.xsd and the schema loaded.
    with pytest.warns(Warning, match="block access"), pytest.raises(XmlValidationError):
        validate_against("<patient>x</patient>", schema)


def test_inline_schema_still_resolves_a_namespace_xmlschema_already_holds() -> None:
    # Anti-vacuity for the confinement: a location-free import of the xml namespace needs no resource.
    schema = (
        f'<xs:schema {_XS} targetNamespace="urn:t">'
        '<xs:import namespace="http://www.w3.org/XML/1998/namespace"/>'
        '<xs:element name="e"><xs:complexType><xs:attribute ref="xml:lang"/></xs:complexType>'
        "</xs:element></xs:schema>"
    )
    assert validate_against('<t:e xmlns:t="urn:t" xml:lang="en"/>', schema).valid


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


def test_relative_path_schema_resolves_its_include_beside_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "inc.xsd").write_text(_CLEAN, encoding="utf-8")
    _write_path_schema(tmp_path / "schemas", "inc.xsd")
    monkeypatch.chdir(tmp_path)
    assert validate_against("<patient>x</patient>", "schemas/main.xsd").valid


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
    assert "XMLResourceBlocked" in _causes(ei.value)


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
    assert "XMLResourceBlocked" in _causes(ei.value)


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
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", str(main))
    # parse_bytes refused it, not only xmlschema's narrower entity check.
    assert "XmlSecurityError" in _causes(ei.value)


@pytest.mark.parametrize(
    "location",
    [
        pytest.param("\\\\nonexist-5537.invalid\\share\\x.xsd", id="unc-backslash"),
        pytest.param("file:////nonexist-5537.invalid/share/x.xsd", id="unc-file-url"),
        pytest.param("\\\\.\\pipe\\nonexist-5537", id="device"),
    ],
)
def test_a_network_or_device_location_is_refused_before_it_is_resolved(
    location: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows realpath opens the path, so resolving one of these would already connect to it.
    resolved: list[str] = []
    real_realpath = os.path.realpath

    def spy(path: Any, *args: Any, **kwargs: Any) -> Any:
        resolved.append(os.fsdecode(path))
        return real_realpath(path, *args, **kwargs)

    main = _write_path_schema(tmp_path, location)
    for source in (main.read_text(encoding="utf-8"), str(main)):
        resolved.clear()
        monkeypatch.setattr(os.path, "realpath", spy)
        with pytest.raises(XmlValidationError) as ei:
            validate_against("<patient>x</patient>", source)
        monkeypatch.setattr(os.path, "realpath", real_realpath)
        assert "XMLResourceBlocked" in _causes(ei.value)
        assert not [p for p in resolved if "nonexist-5537" in p]


@pytest.mark.parametrize(
    "source",
    ["http://127.0.0.1:9/x.xsd", "ftp://127.0.0.1:9/x.xsd", "urn:x-5537:schema"],
)
def test_a_non_file_schema_source_is_refused(source: str) -> None:
    # It used to become a path relative to the working directory, which xmlschema then opened.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", source)
    assert _causes(ei.value)[1] == "ValueError"


@pytest.mark.parametrize("codec", ["utf-16-be", "utf-16-le"])
def test_bomless_utf16_schema_bytes_are_read_as_the_schema(codec: str) -> None:
    # With a declaration the parser detects the encoding from the first bytes and the schema loads.
    declared = ('<?xml version="1.0" encoding="UTF-16"?>' + _CLEAN).encode(codec)
    assert validate_against("<patient>x</patient>", declared).valid
    # Without one it still goes to the hardened parser, never to the filesystem as a path.
    with pytest.raises(XmlValidationError) as ei:
        validate_against("<patient>x</patient>", _CLEAN.encode(codec))
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
