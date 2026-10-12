# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Vault handler keeps the text of the Vault hop's own refusal only (vault BACKLOG #3247).

``vault_failure_text`` decides what a Vault provider's catch-all handler may print about a failure.
It used to keep the text of every ``InsecureHopRefused``. That type is raised across the engine, and
elsewhere its text can echo a host (``transports/rest.py``), so a handler that met one of those
would have printed the host. The hop's own refusals are now a marked subclass,
``VaultHopRefused``, and only that subclass keeps its text.

Three source scans hold the marker to its meaning. No module but ``strict_requests`` calls the
name. ``strict_requests`` calls neither ``InsecureHopRefused`` nor ``enforce_insecure_hop``. And
each marked refusal is built from a shape that cannot interpolate a caller's value. The scans match
a call by name, so an alias or a subclass is outside what they see.

Synthetic data only: the host, key names and wrapped key are made up.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.keyprovider import KeyProviderError
from tests._ast_sites import call_sites, callee_name, parse_source
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

#: ``strict_requests`` imports ``requests`` and ``urllib3`` at module scope.
_needs_the_vault_extra = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_PACKAGE = Path(__file__).resolve().parent.parent / "messagefoundry"
_HOME = _PACKAGE / "transports" / "strict_requests.py"
_MARKER = "VaultHopRefused"

_HOST = "vault.synthetic.test"
#: The shape a refusal takes elsewhere in the engine: it names the host it refused.
_HOST_ECHOING = f"REST cleartext egress: http://{_HOST}:8200 is not loopback; refusing"


def _lines_building(path: Path, name: str) -> list[int]:
    """The lines of ``path`` that call ``name``. A file whose text never spells the name is not
    parsed: code that builds the type has to spell it."""
    text = path.read_text(encoding="utf-8")
    if name not in text:
        return []
    return [call.lineno for call in call_sites(parse_source(text), name)]


def test_only_the_strict_reader_module_builds_the_marked_refusal() -> None:
    elsewhere = {
        str(path.relative_to(_PACKAGE)): lines
        for path in sorted(_PACKAGE.rglob("*.py"))
        if path != _HOME and (lines := _lines_building(path, _MARKER))
    }
    assert elsewhere == {}, f"{_MARKER} is built outside strict_requests.py: {elsewhere}"


@pytest.mark.parametrize("unmarked", ["InsecureHopRefused", "enforce_insecure_hop"])
def test_the_strict_reader_module_builds_no_unmarked_hop_refusal(unmarked: str) -> None:
    """A check added here that raised the base type would lose its text at every handler. The
    shared ``enforce_insecure_hop`` raises the base type, so a call to it counts too."""
    lines = _lines_building(_HOME, unmarked)
    assert lines == [], f"strict_requests.py calls {unmarked} at lines {lines}"
    # The control for these scans: the same scan sees the marked sites in this module, so an
    # empty answer is not the scan seeing nothing at all.
    assert _lines_building(_HOME, _MARKER)


#: Helpers in ``strict_requests`` whose return value is a refusal's whole text. Each takes the
#: connector label and returns it with a fixed reason. Read a helper before adding it here.
_TEXT_HELPERS = frozenset({"_unverifiable_proxy_leg"})


def _is_label_or_constant(node: ast.expr) -> bool:
    """``connector``, ``self._connector``, or a module constant spelled in upper case."""
    if isinstance(node, ast.Name):
        return node.id == "connector" or node.id.isupper()
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "_connector"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _is_fixed_text(call: ast.Call) -> bool:
    """Whether a refusal is built from one argument that can carry only fixed text: a literal, a
    listed helper's result, or an f-string whose holes are the connector label or a constant."""
    if len(call.args) != 1 or call.keywords:
        return False
    text = call.args[0]
    if isinstance(text, ast.Constant):
        return isinstance(text.value, str)
    if isinstance(text, ast.Call):
        return callee_name(text, bare_only=True) in _TEXT_HELPERS
    if isinstance(text, ast.JoinedStr):
        return all(
            _is_label_or_constant(part.value)
            for part in text.values
            if isinstance(part, ast.FormattedValue)
        )
    return False


def test_every_marked_refusal_is_built_from_fixed_text() -> None:
    """The marker means the text names no address, proxy URL, token or reply. This holds each
    site to a shape that cannot interpolate one. It does not read a listed helper's own text."""
    sites = call_sites(parse_source(_HOME.read_text(encoding="utf-8")), _MARKER)
    loose = [site.lineno for site in sites if not _is_fixed_text(site)]
    assert loose == [], f"a marked refusal interpolates something at lines {loose}"
    assert sites, "the scan saw no marked refusal at all"


@pytest.mark.parametrize(
    "source",
    [
        'VaultHopRefused(f"{connector}: proxy {proxy} refused")',
        'VaultHopRefused(f"{connector}: {request.url} refused")',
        "VaultHopRefused(str(exc))",
        'VaultHopRefused("refused: " + url)',
        "VaultHopRefused(_other_helper(connector))",
    ],
)
def test_the_fixed_text_scan_can_fail(source: str) -> None:
    """The control for the scan above: each of these would put a caller's value in the text."""
    (site,) = call_sites(parse_source(source), _MARKER)
    assert not _is_fixed_text(site)


@_needs_the_vault_extra
def test_an_unmarked_hop_refusal_gives_only_its_type_name() -> None:
    from messagefoundry.transports.strict_requests import VaultHopRefused, vault_failure_text

    assert vault_failure_text(InsecureHopRefused(_HOST_ECHOING)) == "InsecureHopRefused"
    # The control: the marked type keeps its text, and it is still the base type to a handler.
    marked = VaultHopRefused("Vault test hop: fixed text")
    assert vault_failure_text(marked) == "Vault test hop: fixed text"
    assert isinstance(marked, InsecureHopRefused)


@_needs_the_vault_extra
def test_the_cleartext_refusal_is_marked_and_keeps_its_wording() -> None:
    """The cleartext refusal used to come from the shared ``enforce_insecure_hop``, which raises
    the base type. The module now builds it, with the text that function gave it."""
    from messagefoundry.transports.strict_requests import (
        _CLEARTEXT_VAULT_HOP,
        VaultHopRefused,
        _refuse_a_cleartext_vault_hop,
    )

    with pytest.raises(VaultHopRefused) as caught:
        _refuse_a_cleartext_vault_hop(f"http://{_HOST}:8200", None, connector="Vault test hop")
    assert str(caught.value) == f"Vault test hop: {_CLEARTEXT_VAULT_HOP}"
    assert _HOST not in str(caught.value)


class _Transit:
    """A Transit backend whose first call fails with ``exc``."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def read_key(self, *, name: str) -> dict[str, Any]:
        raise self._exc


class _Client:
    def __init__(self, exc: Exception) -> None:
        self.secrets = type("_Secrets", (), {"transit": _Transit(exc)})()


def _active_key_failure(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> str:
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    monkeypatch.setattr(keyprovider_vault, "_build_client", lambda addr, token: _Client(exc))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    return str(caught.value)


@_needs_the_vault_extra
def test_the_key_provider_does_not_print_a_host_from_an_unmarked_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = _active_key_failure(monkeypatch, InsecureHopRefused(_HOST_ECHOING))
    assert _HOST not in text, text
    assert text.endswith("InsecureHopRefused."), text


@_needs_the_vault_extra
def test_the_key_provider_keeps_the_text_of_a_marked_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above: the handler under test does keep a refusal's text."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    text = _active_key_failure(monkeypatch, VaultHopRefused("Vault test hop: fixed text"))
    assert text.endswith("Vault test hop: fixed text."), text
