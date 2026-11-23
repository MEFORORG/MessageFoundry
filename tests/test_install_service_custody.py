# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-service.ps1 under ``[store].key_provider = 'host'`` (vault BACKLOG #3411, key custody S3
slice B3c).

The installer refuses SYSTEM, LOCAL SERVICE and NETWORK SERVICE, which the host provider refuses as
the engine account, before anything acts. It does not check the provider's refusal of a non-local
account under enforce. Behaviour runs the script's own functions, extracted by AST, through ``pwsh``; the
call sites are read by AST, since no test runs the script body.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

import messagefoundry.service as svc
from tests.test_service_install_manifest import (
    _extract,
    _ok,
    _preflight_facts,
    _psq,
    _script_text,
    _sole_call,
)

_SCRIPT = svc.install_script_path()

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)

_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"

# (settings file text, what the installer must read as [store].key_provider)
_SETTINGS: list[tuple[str, str | None]] = [
    ('[store]\nkey_provider = "host"\n', "host"),
    ("[store]\nkey_provider = 'host'   # the custody provider\n", "host"),
    ('[api]\nport = 1\n\n[ store ]\nbackend = "sqlite"\n  key_provider="host"\n', "host"),
    ('[store]\n"key_provider" = "host"\n', "host"),
    ('store.key_provider = "host"\n[api]\nport = 1\n', "host"),
    ('store = { backend = "sqlite", key_provider = "host" }\n', "host"),
    (_BOM + '[store]\nkey_provider = "host"\n', "host"),
    ('[store]\nkey_provider = "auto"\n', "auto"),
    ('[store]\nbackend = "sqlite"\n', None),
    ('[store.tls]\nkey_provider = "host"\n', None),
    ('[api]\nkey_provider = "host"\n', None),
    ('[store]\n[[alerts.sinks]]\nkey_provider = "host"\n', None),
    ('[store]\n# key_provider = "host"\n', None),
    ('[store]\nother_key_provider = "host"\n', None),
    # TOML names are case-sensitive, and a key in a nested inline table is not [store]'s.
    ('[STORE]\nkey_provider = "host"\n', None),
    ('[store]\nKEY_PROVIDER = "host"\n', None),
    ('store = { tls = { key_provider = "host" } }\n', None),
    # Text that only looks like the key: a comment, a string value, a multi-line string.
    ('store = { backend = "sqlite" }  # was key_provider = "host"\n', None),
    ('store = { backend = "sqlite", note = "x key_provider = \'host\'" }\n', None),
    ('[api]\nnote = """\n[store]\nkey_provider = "host"\n"""\n', None),
    # Lines that only look like a table header do not move the reader out of [store].
    ('[store]\npairs = [\n  ["a", "b"]\n]\nkey_provider = "host"\n', "host"),
    # A one-element nested array line has a header's shape, inside [store] and outside it.
    ('[store]\nretired = [\n  ["k1"]\n]\nkey_provider = "host"\n', "host"),
    ('[store]\nn = [\n  [1],\n  [2]\n]\nkey_provider = "host"\n', "host"),
    ('[api]\nhosts = [\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ('[api]\nhosts = [ # "]"\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ('[store]\nnote = """\n[api]\n"""\nkey_provider = "host"\n', "host"),
    # The array is open after a multi-line string ends, so its element lines are not headers.
    ('[store]\nx = [ """\na""",\n  [1]\n]\nkey_provider = "host"\n', "host"),
    ('[api]\nx = [ """\nq""",\n  ["store"]\n]\nkey_provider = "host"\n', None),
    ("[store]\nx = [ '''\nq''', [\n  [[1]]\n]]\nkey_provider = \"host\"\n", "host"),
    ('[store]\nx = [\n"""a\n""", [\n[[1]]]]\nkey_provider = "host"\n', "host"),
    # A triple quote that opens no multi-line string: in a one-line string, in a comment.
    ('[api]\nnote = \'say """\'\n[store]\nkey_provider = "host"\n', "host"),
    ("# don't '''\n[store]\nkey_provider = \"host\"\n", "host"),
    ('[store]\nn = """a""""\nkey_provider = "host"\n', "host"),
    ('[store]\nn = """a\\"""\n[api]\n"""\nkey_provider = "host"\n', "host"),
    # Headers: tabs, quoted keys, arrays of tables. One the reader cannot classify ends [store].
    ('[\tstore\t]\nkey_provider = "host"\n', "host"),
    ('[store]\n[\tapi\t]\nkey_provider = "host"\n', None),
    ('[store]\n["a:b"]\nkey_provider = "host"\n', None),
    ('["sto re"]\nkey_provider = "host"\n', None),
    ('[ "store" ]\nkey_provider = "host"\n', "host"),
    ('[store]\n["\\u0061pi"]\nkey_provider = "host"\n', None),
    ('[store]\n[[array.of.tables]]\nkey_provider = "host"\n', None),
    ('[[array.of.tables]]\nx = 1\n[store]\nkey_provider = "host"\n', "host"),
    ("", None),
]


def test_the_settings_reader_finds_the_key_provider(tmp_path: Path) -> None:
    """Every case is a real settings file whose [store].key_provider, under Python's own TOML
    reader, is the value the installer must read."""
    assert _SCRIPT is not None
    for text, expected in _SETTINGS:
        store = tomllib.loads(text.removeprefix(_BOM)).get("store", {})
        assert store.get("key_provider") == expected, text
    paths = []
    for i, (text, _) in enumerate(_SETTINGS):
        p = tmp_path / f"settings-{i}.toml"
        p.write_bytes(text.encode("utf-8"))
        paths.append(str(p))
    body = (
        "  $out = @(foreach ($p in @("
        + ", ".join(_psq(p) for p in paths)
        + ")) { $v = Get-SettingsKeyProvider -Path $p; if ($null -eq $v) { '<none>' } else { $v } })\n"
        "  ConvertTo-Json -InputObject $out -Compress\n"
    )
    got = json.loads(_ok(_extract(_SCRIPT, ["Get-SettingsKeyProvider"], body), tmp_path))
    want = ["<none>" if e is None else e for _, e in _SETTINGS]
    assert got == want, list(zip([t for t, _ in _SETTINGS], got, want, strict=True))


# (-ServiceAccount, -AllowLocalSystem, refused)
_ACCOUNTS: list[tuple[str, bool, bool]] = [
    ("", True, True),
    ("", False, False),
    (r"NT SERVICE\MessageFoundry", False, False),
    (r"NT SERVICE\MessageFoundry", True, False),  # an explicit -ServiceAccount wins
    (r"CONTOSO\svc-mefor$", False, False),
    ("LocalSystem", False, True),
    (r".\LocalSystem", False, True),
    (r"NT AUTHORITY\SYSTEM", False, True),
    ("SYSTEM", False, True),
    (r"nt authority\localservice", False, True),
    (r"NT AUTHORITY\LOCAL SERVICE", False, True),
    (r"NT AUTHORITY\NetworkService", False, True),
    (r"NT AUTHORITY\NETWORK SERVICE", False, True),
    ("*S-1-5-18", False, True),
    ("S-1-5-20", False, True),
]


def test_the_host_provider_refuses_the_shared_accounts(tmp_path: Path) -> None:
    """One pwsh run for every case: the function is pure."""
    assert _SCRIPT is not None
    calls = "\n".join(
        f"  $out += [string](Get-HostCustodyAccountProblem -ServiceAccount {_psq(account)} "
        f"-AllowLocalSystem:{'$true' if allow else '$false'})"
        for account, allow, _ in _ACCOUNTS
    )
    body = f"  $out = @()\n{calls}\n  ConvertTo-Json -InputObject $out -Compress\n"
    got = json.loads(_ok(_extract(_SCRIPT, ["Get-HostCustodyAccountProblem"], body), tmp_path))
    assert [bool(p) for p in got] == [r for _, _, r in _ACCOUNTS], list(
        zip(_ACCOUNTS, got, strict=False)
    )


def test_the_installer_refuses_before_anything_acts(tmp_path: Path) -> None:
    """CALL-SITE guard: the refusal reads the service's own environment first, then the settings
    file the service is registered with, and throws before NSSM is resolved or the install is
    built."""
    facts = _preflight_facts(tmp_path)
    text = _script_text().replace("\r\n", "\n")
    reader = _sole_call(facts, "Get-SettingsKeyProvider")
    assert "-Path $ServiceConfig" in reader["text"], reader["text"]
    problem = _sole_call(facts, "Get-HostCustodyAccountProblem")
    assert "-ServiceAccount $ServiceAccount" in problem["text"], problem["text"]
    assert "-AllowLocalSystem:$AllowLocalSystem" in problem["text"], problem["text"]
    registered = next(
        c
        for c in facts["commands"]
        if c["name"] == "Get-RegisteredEnvironmentValue" and "MEFOR_STORE_KEY_PROVIDER" in c["text"]
    )
    assert registered["start"] < reader["start"]
    refusal = text.index('throw ("$custodyAccountProblem, and $namedBy')
    for later in (
        "if ($BuildsInstall) {\n    # AFTER the normalization",
        "if (-not $BuildsInstall) { $NssmPath = Resolve-Nssm",
        "New-Item -ItemType Directory -Force -Path $DataDir",
    ):
        assert refusal < text.index(later), later
    # The settings file is known to exist before it is read.
    assert text.index("Service settings file not found at: $ServiceConfig") < refusal
