# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Vault handler keeps the text of the Vault hop's own refusal only (vault BACKLOG #3247).

``vault_failure_text`` decides what a Vault provider's catch-all handler may print about a failure.
It used to keep the text of every ``InsecureHopRefused``. That type is raised across the engine, and
elsewhere its text can echo a host (``transports/rest.py``), so a handler that met one of those
would have printed the host. The hop's own refusals are now a marked subclass,
``VaultHopRefused``, and only that subclass keeps its text.

Two source scans hold the marker to its meaning: no module but ``strict_requests`` builds one, and
``strict_requests`` builds no bare ``InsecureHopRefused``.

Synthetic data only: the host, key names and wrapped key are made up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.keyprovider import KeyProviderError
from tests._ast_sites import call_sites, parse_source
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


def test_the_strict_reader_module_builds_no_unmarked_hop_refusal() -> None:
    """A check added here that raised the base type would lose its text at every handler."""
    unmarked = _lines_building(_HOME, "InsecureHopRefused")
    assert unmarked == [], f"strict_requests.py builds a bare InsecureHopRefused at {unmarked}"
    # The control for both scans: the same scan sees the marked sites in this module, so an empty
    # answer is not the scan seeing nothing at all.
    assert _lines_building(_HOME, _MARKER)


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
