# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 12.1.1 — every declared browser-TLS floor must be backed by a fence that PINS it.

In Posture-B (``[api].tls_terminated_upstream``) the reverse proxy terminates browser TLS, so the
engine observes **nothing** about that hop: ``[api].proxy_tls_min_version`` is an operator
*attestation* validated only for string coherence (``config/tls_policy.validate_proxy_tls_posture``).
The only artifacts standing behind that attestation are the reference proxy configurations we ship —
which for a long time named no protocol or cipher policy at all, so an operator copying one verbatim
got whatever their nginx/Caddy/SChannel build defaulted to (TLS 1.0/1.1 on older builds) while the
engine claimed a 1.2 floor.

This module makes the pinning a **tested property of the documentation set**:

* each of the three reference fences (nginx / Caddy / IIS+ARR) names an explicit protocol floor, a
  forward-secret cipher policy, and the engine's own approved key-exchange groups;
* the nginx cipher list is run through the **engine's own** ``validate_tls_ciphers`` gate, so
  "forward-secret" means exactly what it means everywhere else in the codebase rather than whatever
  the doc author believed;
* the IIS/ARR SCHANNEL procedure cannot *silently do nothing* — the two shapes that can (a
  ``Set-ItemProperty`` against a policy key that does not exist on an un-GPO'd host, and a
  ``Disable-TlsCipherSuite`` pipeline mutating the collection ``Get-TlsCipherSuite`` is streaming)
  are asserted out, and each write must be read back; and
* **every** document that prints a copy-pasteable ``proxy_tls_min_version`` declares the floor the
  fences it references actually pin — the coherence check no code path can perform, because nothing
  in the engine can read the operator's proxy config.

That last property is derived **twice**, from opposite ends, because the residual has two shapes and
an earlier revision of this module only guarded one of them:

* keyed on the **declaration** (``_declaring_docs``) — a page that prints the key must declare the
  floor its fences pin, so a floor is never *over*-claimed; and
* keyed on the **posture** (``_posture_docs``) — a page that prints a ``tls_terminated_upstream =
  true`` block must print the key **at all**. That is the *worse* shape: no attestation, no fence,
  and no link to one. Two operator-facing pages shipped exactly that (``docs/REMOTE-CONSOLE.md`` and
  ``docs/CONTAINER-EXPOSURE-EVALUATION.md``) while every declaration-keyed guard here was green.

Both derivations walk **the whole repository**, not ``docs/``. The floor is copy-pasteable from
anywhere — a ``README.md`` or an IDE walkthrough that prints an ``[api]`` block ships the identical
defect — and scoping the derivation to one subtree is precisely what let those two pages through.
The sets are **derived**, not listed, so a new site is covered the day it is written; a companion
guard fails a declaration printed outside a ```toml fence, where the derivation could not see it,
and :data:`_KNOWN_POSTURE_B_PAGES` keeps a derivation that has quietly gone empty from reporting a
pass.

Structural + settings-load assertions over Markdown. No engine behaviour is exercised and no network
is touched.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DOCS = _ROOT / "docs"
_DOC = _DOCS / "security" / "OFF-LOOPBACK-DEPLOYMENT.md"

if not _DOC.exists():
    # Same deny-list/vault guard as tests/test_off_loopback_runbook.py, and it must sit BEFORE the import
    # of that module: it skips at module level too, so importing it first would make this file's skip an
    # incidental side effect of someone else's guard rather than its own stated reason.
    pytest.skip(
        "docs/security/OFF-LOOPBACK-DEPLOYMENT.md is private-only (OSS-mirror deny-list / vault)",
        allow_module_level=True,
    )

from tests.test_off_loopback_runbook import _TOML_FENCE_RE, _dedent  # noqa: E402

#: Directory names the repo-wide Markdown walk never descends into: build output, dependency trees
#: and caches. A vendored or generated copy of a page under one of these is not something we ship.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "out",
        "dist",
        "build",
        "htmlcov",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".vscode-test",
    }
)

#: The declared floor of record. Every fence must permit this version and nothing below it, and the
#: engine block must declare exactly this string (the LOWEST version the fences still permit).
_FLOOR = "1.2"

#: Protocol versions no fence may enable. SSL 2.0/3.0 are dead; TLS 1.0/1.1 are below the NIST
#: SP 800-52r2 floor the engine's own ``_APPROVED_TLS_MIN_VERSIONS`` encodes.
_BELOW_FLOOR = ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _repo_markdown() -> list[Path]:
    """Every Markdown page in the repository, minus build/dependency trees (:data:`_SKIP_DIRS`).

    Deliberately **not** ``_DOCS.rglob``: an ``[api]`` block is copy-pasteable from ``README.md``,
    ``docker/README.md``, an ``ide/`` walkthrough or a packaging README just as readily as from a
    page under ``docs/``, and a floor printed there would ship entirely unheld.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(_ROOT):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
        found.extend(Path(dirpath) / name for name in filenames if name.endswith(".md"))
    return sorted(found)


def _doc() -> str:
    return _text(_DOC)


def _fences(text: str, lang: str) -> list[str]:
    """Bodies of every column-0 ```<lang> fence in ``text``."""
    pattern = re.compile(rf"^```{lang}[ \t]*$\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)
    return [str(m) for m in pattern.findall(text)]


def _fence(lang: str, text: str | None = None) -> str:
    """The body of the single column-0 ```<lang> fence in the runbook (or in ``text``)."""
    matches = _fences(_doc() if text is None else text, lang)
    assert len(matches) == 1, (
        f"expected exactly one ```{lang} fence in {_DOC.name}, found {len(matches)} — the reference "
        f"proxy configs are single-sourced; a second one would drift from this guard"
    )
    return matches[0]


def _section_opt(heading_prefix: str, text: str) -> str | None:
    """Everything under the first heading starting with ``heading_prefix``, up to the next ``### ``."""
    start = text.find(heading_prefix)
    if start == -1:
        return None
    nxt = text.find("\n### ", start + len(heading_prefix))
    return text[start:] if nxt == -1 else text[start:nxt]


def _section(heading_prefix: str, text: str | None = None) -> str:
    body = _section_opt(heading_prefix, _doc() if text is None else text)
    assert body is not None, f"runbook section starting {heading_prefix!r} missing from {_DOC.name}"
    return body


def _directive_opt(body: str, name: str) -> str | None:
    """The value of an ``<name> <value>;`` nginx directive, or ``None`` when absent."""
    match = re.search(rf"^\s*{name}\s+([^;]+);", body, re.MULTILINE)
    return None if match is None else " ".join(match.group(1).split())


def _directive(body: str, name: str) -> str:
    """The value of an ``<name> <value>;`` nginx directive (assert-fails when absent)."""
    value = _directive_opt(body, name)
    assert value is not None, (
        f"the nginx reference fence has no `{name}` directive — without it nginx negotiates whatever "
        f"the build default permits while [api].proxy_tls_min_version claims a floor (ASVS 12.1.1)"
    )
    return value


def _normalize_version(token: str) -> str:
    """``TLSv1.2`` / ``tls1.2`` / ``TLS 1.2`` → ``1.2`` (the ``proxy_tls_min_version`` spelling)."""
    return token.strip().lower().removeprefix("tlsv").removeprefix("tls").strip()


def _as_tuple(version: str) -> tuple[int, ...]:
    """``"1.2"`` → ``(1, 2)`` so floors compare numerically, not lexically."""
    return tuple(int(part) for part in version.split("."))


# ── nginx ────────────────────────────────────────────────────────────────────────────────────────


def test_nginx_fence_pins_the_tls_version_floor() -> None:
    versions = sorted(
        _normalize_version(t) for t in _directive(_fence("nginx"), "ssl_protocols").split()
    )
    assert versions == ["1.2", "1.3"], (
        f"the nginx fence must pin `ssl_protocols TLSv1.2 TLSv1.3;`, got {versions} — the browser-facing "
        f"floor is the whole subject of ASVS 12.1.1 and [api].proxy_tls_min_version only attests it"
    )


def test_nginx_fence_binds_its_floor_to_the_listening_socket() -> None:
    """The pinned floor must actually apply, not merely appear.

    nginx resolves the TLS protocol version and cipher policy from the DEFAULT server for a listening
    socket — version negotiation precedes SNI, so nginx does not yet know which vhost the client
    wanted. ``ssl_protocols``/``ssl_ciphers``/``ssl_ecdh_curve`` inside a non-default ``server{}`` on a
    shared :443 are therefore inert, while ``[api].proxy_tls_min_version`` keeps attesting the floor —
    a runbook that reads correct and deploys wrong, which is worse than one that reads wrong.

    Satisfied either by marking the socket owner or by hoisting the directives into ``http{}`` (all
    four are http-context-valid and inherit), so both shapes are accepted.
    """
    fence = _fence("nginx")
    marks_socket_owner = re.search(r"^\s*listen\s+[^;#]*\bdefault_server\b", fence, re.MULTILINE)
    hoisted = re.search(r"^\s*http\s*\{", fence, re.MULTILINE)
    assert marks_socket_owner or hoisted, (
        "the nginx fence pins ssl_protocols/ssl_ciphers inside a non-default server{} on a bare "
        "`listen 443 ssl;`. An operator copying it onto a host that already serves :443 gets the "
        "other vhost's TLS policy while the engine still declares this floor. Use "
        "`listen 443 ssl default_server;`, or hoist the four directives into `http {}`."
    )


def test_nginx_fence_cipher_list_is_forward_secret_by_the_engines_own_gate() -> None:
    """Run the documented ``ssl_ciphers`` string through the validator the engine applies to its own.

    This is the assertion that cannot be satisfied by a plausible-looking edit: the string is handed
    to OpenSSL and every suite it resolves to must use an (EC)DHE key exchange, exactly as
    ``[api].tls_ciphers`` / ``[api].proxy_tls_ciphers`` are held. A future lane declaring
    ``proxy_tls_ciphers`` rides on this same string.
    """
    from messagefoundry.config.tls_policy import validate_tls_ciphers

    ciphers = _directive(_fence("nginx"), "ssl_ciphers")
    validate_tls_ciphers(ciphers)  # raises ValueError on a non-forward-secret / unparseable list
    assert "ECDHE" in ciphers, (
        "the nginx ssl_ciphers list names no ECDHE suite — a DHE-only list is forward-secret but is "
        "not what the reference config intends to document"
    )


def test_nginx_fence_pins_the_engines_approved_kex_groups() -> None:
    from messagefoundry.config.tls_policy import APPROVED_KEX_GROUPS

    curves = _directive(_fence("nginx"), "ssl_ecdh_curve")
    assert curves == APPROVED_KEX_GROUPS, (
        f"the nginx fence pins key-exchange groups {curves!r} but the engine pins "
        f"{APPROVED_KEX_GROUPS!r} on its own contexts (config/tls_policy.APPROVED_KEX_GROUPS) — the "
        f"browser hop and the engine hop must not drift apart (ASVS 11.6.2)"
    )


def _nginx_floor(text: str) -> str | None:
    """The lowest TLS version the nginx fence in ``text`` still permits (``None``: no such fence)."""
    fences = _fences(text, "nginx")
    if not fences:
        return None
    protocols = _directive_opt(fences[0], "ssl_protocols")
    assert protocols is not None, "an nginx reference fence names no `ssl_protocols` floor"
    return min((_normalize_version(t) for t in protocols.split()), key=_as_tuple)


# ── Caddy ────────────────────────────────────────────────────────────────────────────────────────


def _caddy_protocols(body: str) -> list[str]:
    match = re.search(r"^\s*protocols\s+(.+)$", body, re.MULTILINE)
    assert match is not None, (
        "the Caddy reference fence has no `protocols` sub-directive. Caddy's default is already "
        "TLS 1.2+, but the reference config must SAY so — [api].proxy_tls_min_version is an "
        "attestation and this file is the only artifact behind it (ASVS 12.1.1)"
    )
    return [_normalize_version(t) for t in match.group(1).split()]


def test_caddy_fence_pins_the_tls_version_floor() -> None:
    versions = sorted(_caddy_protocols(_fence("caddy")))
    assert versions == ["1.2", "1.3"], (
        f"the Caddy fence must pin `protocols tls1.2 tls1.3`, got {versions}"
    )


def test_caddy_fence_offers_only_forward_secret_suites() -> None:
    body = _fence("caddy")
    match = re.search(r"^\s*ciphers\s+(.+)$", body, re.MULTILINE)
    assert match is not None, (
        "the Caddy reference fence has no `ciphers` sub-directive (ASVS 11.6.2)"
    )
    suites = match.group(1).split()
    assert suites, "the Caddy `ciphers` directive names no suite"
    non_fs = [s for s in suites if "_ECDHE_" not in s and "_DHE_" not in s]
    assert not non_fs, (
        f"the Caddy fence offers suite(s) with a non-forward-secret key exchange: {non_fs} — the "
        f"engine's own validate_tls_ciphers would reject the equivalent OpenSSL list"
    )


def _caddy_floor(text: str) -> str | None:
    fences = _fences(text, "caddy")
    if not fences:
        return None
    return min(_caddy_protocols(fences[0]), key=_as_tuple)


# ── IIS + ARR (SChannel) ─────────────────────────────────────────────────────────────────────────

_IIS_HEADING = "### IIS + Application Request Routing (ARR)"
_SCHANNEL_FOREACH_RE = re.compile(
    r"foreach \(\$proto in (?P<protocols>[^)]*)\)\s*\{(?P<body>.*?)^\}", re.DOTALL | re.MULTILINE
)
#: The SChannel/CNG spelling of each OpenSSL group name in ``APPROVED_KEX_GROUPS``. The registry
#: policy value takes CNG names, so the two lists can only be compared through this mapping.
_CNG_GROUP_NAMES = {"X25519": "curve25519", "secp384r1": "NistP384", "secp256r1": "NistP256"}
#: The machine-global SSL policy key the key-exchange groups are written to. Absent on a host with no
#: "SSL Cipher Suite Order" GPO — which is why the procedure has to create it before writing.
_SSL_POLICY_KEY = r"HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"


def _schannel_protocol_state(section: str) -> dict[str, int]:
    """``{'TLS 1.0': 0, 'TLS 1.2': 1, ...}`` parsed out of an IIS section's SCHANNEL PowerShell."""
    assert "SCHANNEL\\Protocols" in section, (
        "the IIS/ARR section names no SCHANNEL protocol policy. IIS has no per-site `ssl_protocols` "
        "equivalent — without the machine-global SCHANNEL step the Windows-native fence pins nothing "
        "at all, and it is the fence a Windows/AD estate is most likely to use (ASVS 12.1.1)"
    )
    state: dict[str, int] = {}
    for match in _SCHANNEL_FOREACH_RE.finditer(section):
        enabled = re.search(r"-Name '?Enabled'?\s+-Value (\d+)", match.group("body"))
        assert enabled is not None, (
            "a SCHANNEL protocol loop in the IIS section sets no `Enabled` value — it would silently "
            "do nothing"
        )
        for proto in re.findall(r"'([^']+)'", match.group("protocols")):
            state[proto] = int(enabled.group(1))
    assert state, f"no SCHANNEL protocol loop found under {_IIS_HEADING!r}"
    return state


def _iis_floor(text: str) -> str | None:
    section = _section_opt(_IIS_HEADING, text)
    if section is None:
        return None
    enabled = [proto for proto, on in _schannel_protocol_state(section).items() if on]
    assert enabled, "the IIS SCHANNEL step enables no TLS version at all"
    return min((_normalize_version(p) for p in enabled), key=_as_tuple)


@pytest.mark.parametrize("protocol", _BELOW_FLOOR)
def test_iis_section_disables_every_protocol_below_the_floor(protocol: str) -> None:
    state = _schannel_protocol_state(_section(_IIS_HEADING))
    assert state.get(protocol) == 0, (
        f"the IIS/ARR SCHANNEL step does not disable {protocol!r} (state={state.get(protocol)!r}); "
        f"[api].proxy_tls_min_version = {_FLOOR!r} would then be a false attestation on a Windows front"
    )


def test_iis_section_enables_the_declared_floor() -> None:
    state = _schannel_protocol_state(_section(_IIS_HEADING))
    assert state.get(f"TLS {_FLOOR}") == 1, (
        f"the IIS/ARR SCHANNEL step must explicitly enable 'TLS {_FLOOR}' (the declared floor); "
        f"parsed state: {state}"
    )


def test_iis_section_restricts_the_cipher_suites_to_forward_secret_ones() -> None:
    section = _section(_IIS_HEADING)
    assert "Disable-TlsCipherSuite" in section, (
        "the IIS/ARR section never narrows the machine's TLS cipher suites — SChannel's default set "
        "includes static-RSA key transport, which is not forward-secret (ASVS 11.6.2)"
    )
    kept = re.findall(r"'(TLS_[A-Z0-9_]+)'", section)
    assert kept, "the IIS/ARR section names no cipher suite to keep"
    non_fs = [s for s in kept if not (s.startswith("TLS_ECDHE_") or s.startswith("TLS_AES_"))]
    assert not non_fs, (
        f"the IIS/ARR keep-list names non-forward-secret suite(s): {non_fs} (TLS_RSA_* is static-RSA "
        f"key transport; only TLS_ECDHE_* and the TLS 1.3 TLS_AES_*/TLS_CHACHA20_* suites qualify)"
    )


def test_iis_cipher_sweep_does_not_mutate_the_collection_it_enumerates() -> None:
    """``Get-TlsCipherSuite | ... | Disable-TlsCipherSuite`` can silently skip suites.

    The pipeline is lazy: ``Disable-TlsCipherSuite`` rewrites the machine's cipher-suite list while
    ``Get-TlsCipherSuite`` is still enumerating from it, so entries can be stepped over. The result
    is a host that reads as pinned and still offers static-RSA key transport to browsers — and the
    procedure reboots immediately afterwards. Require the snapshot-then-loop shape instead: the
    enumerated variable must have been assigned from an ``@(Get-TlsCipherSuite ...)`` array
    subexpression *before* the loop that disables anything.
    """
    section = _section(_IIS_HEADING)

    piped = re.search(
        r"Get-TlsCipherSuite[^\n]*\|[\s\S]{0,120}?ForEach-Object\s*\{\s*Disable-TlsCipherSuite",
        section,
    )
    assert piped is None, (
        "the IIS/ARR cipher sweep pipes Get-TlsCipherSuite straight into Disable-TlsCipherSuite. "
        "That mutates the collection being enumerated and can SKIP suites, leaving non-forward-secret "
        "key exchange enabled on the browser-facing hop while the step appears to have succeeded. "
        "Snapshot to an array first, then loop over the snapshot."
    )

    loop = re.search(
        r"foreach \(\$(?P<item>\w+) in \$(?P<source>\w+)\)\s*\{[^}]*Disable-TlsCipherSuite", section
    )
    assert loop is not None, (
        "the IIS/ARR section has no `foreach ($x in $snapshot) { ... Disable-TlsCipherSuite ... }` "
        "sweep — the suites are never narrowed, or they are narrowed in a shape this guard cannot "
        "prove is snapshot-based"
    )
    snapshot = re.search(rf"\${loop.group('source')}\s*=\s*@\(\s*Get-TlsCipherSuite", section)
    assert snapshot is not None and snapshot.start() < loop.start(), (
        f"the sweep loops over ${loop.group('source')} but that variable is never assigned from an "
        f"`@(Get-TlsCipherSuite ...)` snapshot before the loop — without the array subexpression the "
        f"enumeration is still lazy over the live list and can skip entries"
    )

    # The verification must live between the sweep and the next numbered step, and it must be CODE.
    # Comments are stripped first on purpose: the shape this replaced was a comment claiming the list
    # "reads back", which is a promise, not a check the operator ever runs.
    tail = section[loop.end() :]
    end = tail.find("\n# 4.")
    region = tail if end == -1 else tail[:end]
    code = "\n".join(ln for ln in region.splitlines() if not ln.strip().startswith("#"))
    assert "Get-TlsCipherSuite" in code and "Write-Warning" in code, (
        "no executable verification follows the cipher sweep. A comment saying the effective list "
        "can be read back is not verification — the operator reboots at the next step, so the "
        "procedure must re-read Get-TlsCipherSuite and Write-Warning anything still enabled. "
        f"Found between the sweep and step 4:\n{region.strip()!r}"
    )


def test_iis_kex_group_pinning_cannot_silently_no_op() -> None:
    """The ``EccCurves`` write must create its key, surface its error, and be read back.

    ``HKLM:\\SOFTWARE\\Policies\\...\\SSL\\00010002`` does not exist on a freshly-built Windows
    Server unless an "SSL Cipher Suite Order" GPO was applied. A bare ``Set-ItemProperty`` against it
    raises ItemNotFound; with ``-ErrorAction SilentlyContinue`` that error is swallowed and the
    operator is told the engine's approved groups are pinned when nothing was written at all.
    """
    section = _section(_IIS_HEADING)
    assert _SSL_POLICY_KEY in section, (
        f"the IIS/ARR section no longer names the SSL policy key {_SSL_POLICY_KEY!r} where the "
        f"key-exchange groups are pinned"
    )
    assert "-ErrorAction SilentlyContinue" not in section, (
        "the IIS/ARR procedure silences an error with -ErrorAction SilentlyContinue. Every step in "
        "this block is machine-global TLS policy; a silenced failure is a step the operator believes "
        "ran. Use -ErrorAction Stop inside try/catch and report the failure."
    )

    write = section.find("-Name 'EccCurves'")
    assert write != -1, (
        "the IIS/ARR section pins no EccCurves value — the Windows fence would negotiate whatever "
        "key-exchange groups SChannel defaults to while nginx/Caddy pin APPROVED_KEX_GROUPS"
    )
    statement = section.rfind("Set-ItemProperty", 0, write)
    assert statement != -1, "the EccCurves value is not written by a Set-ItemProperty"

    # The New-Item must create THE KEY THIS WRITE TARGETS. Matching any `New-Item ... -Force` would
    # be satisfied by the SCHANNEL protocol loops further up, which create a different hive entirely
    # — the exact near-miss that let the unguarded version ship.
    target = re.search(r"-Path\s+(?P<path>\S+)", section[statement : write + 400])
    assert target is not None, "the EccCurves Set-ItemProperty names no -Path"
    path_token = target.group("path")
    create = re.search(rf"New-Item\s+-Path\s+{re.escape(path_token)}[^\n]*-Force", section)
    assert create is not None and create.start() < statement, (
        f"the EccCurves write targets {path_token} but no `New-Item -Path {path_token} ... -Force` "
        f"creates it first. That policy key is ABSENT on a host with no SSL Cipher Suite Order GPO, "
        f"so the write raises ItemNotFound and the approved key-exchange groups are silently left "
        f"unpinned while the operator is told they were applied."
    )
    if path_token.startswith("$"):
        assign = re.search(rf"{re.escape(path_token)}\s*=\s*'(?P<key>[^']+)'", section)
        assert assign is not None and assign.group("key") == _SSL_POLICY_KEY, (
            f"{path_token} is not assigned the SSL policy key {_SSL_POLICY_KEY!r} — the created and "
            f"written key would not be the one SChannel reads its curve order from"
        )
    readback = re.search(r"Get-ItemProperty[^\n]*EccCurves", section[write:])
    assert readback is not None, (
        "nothing reads the EccCurves value back after writing it. The write is the one step here "
        "with no client-side verification after the reboot, so the procedure must print what landed."
    )


def test_iis_section_pins_the_engines_approved_kex_groups() -> None:
    """The CNG curve names must be exactly ``APPROVED_KEX_GROUPS``, in the engine's own order."""
    from messagefoundry.config.tls_policy import APPROVED_KEX_GROUPS

    section = _section(_IIS_HEADING)
    match = re.search(r"-Name 'EccCurves'.*?-Value @\((?P<groups>[^)]*)\)", section, re.DOTALL)
    assert match is not None, "the IIS/ARR section's EccCurves write names no -Value @(...) list"
    curves = re.findall(r"'([^']+)'", match.group("groups"))
    expected = [_CNG_GROUP_NAMES[g] for g in APPROVED_KEX_GROUPS.split(":")]
    assert curves == expected, (
        f"the IIS/ARR fence pins key-exchange groups {curves} but the engine pins "
        f"{APPROVED_KEX_GROUPS!r} on its own contexts, which is {expected} in SChannel's CNG names "
        f"(config/tls_policy.APPROVED_KEX_GROUPS). Order is preference order — keep them identical "
        f"so the browser hop and the engine hop do not drift apart (ASVS 11.6.2)."
    )


# ── every declared floor must match the fences behind it ─────────────────────────────────────────
#
# The residual this module closes is "the browser-facing TLS version floor is an operator
# DECLARATION, not enforcement". Pinning the fences in one document does not close it while a second
# operator-facing page prints its own [api] block: an operator following that page gets exactly the
# defect back. So the declaration sites are DERIVED from docs/ rather than listed, and each one is
# held to the fences it (or the document it references) actually pins.

#: A copy-pasteable ``proxy_tls_min_version = "<v>"`` assignment at the start of a line. Prose
#: mentions (```[api].proxy_tls_min_version` is an attestation``) never match: the key must open
#: the line, exactly as it does in a config file.
_DECLARATION_RE = re.compile(
    r'^[ \t]*proxy_tls_min_version[ \t]*=[ \t]*"(?P<version>[0-9.]+)"', re.MULTILINE
)
#: A relative Markdown link to another ``.md`` file, with any ``#anchor`` discarded.
_MD_LINK_RE = re.compile(r"\]\((?P<target>[^)\s#]+\.md)(?:#[^)\s]*)?\)")
#: The Posture-B declaration itself: ``tls_terminated_upstream = true`` opening a line, exactly as it
#: does in a config file. This is what makes a block *subject* to the floor requirement, whether or
#: not it goes on to declare one — the half a declaration-keyed derivation is blind to.
_POSTURE_RE = re.compile(r"^[ \t]*tls_terminated_upstream[ \t]*=[ \t]*true[ \t]*$", re.MULTILINE)
#: Pages that ship a copy-pasteable Posture-B block today. The derivations above are the mechanism;
#: this is the FLOOR under them. Both guards are parametrized over a derived set, and a parametrize
#: list that has gone empty is reported by pytest as a skip, not a failure — so a page that quietly
#: drops its block or its declaration would close this cell by making the guard vacuous. Removing a
#: name here is a deliberate act with a reason, which is the point.
_KNOWN_POSTURE_B_PAGES = frozenset(
    {
        "OFF-LOOPBACK-DEPLOYMENT.md",  # the runbook: the fences themselves + the engine block
        "REMOTE-CONSOLE-EXPOSURE.md",  # §2 R2, the recommended exposed-console configuration
        "REMOTE-CONSOLE.md",  # the public "operate the engine from a remote PC" landing page
        "CONTAINER-EXPOSURE-EVALUATION.md",  # § exact required config per topology, block (b)
    }
)


def _declarations(text: str) -> list[tuple[int, str, str]]:
    """``(line, block, version)`` for every floor declared inside a ```toml fence of ``text``."""
    found: list[tuple[int, str, str]] = []
    for fence in _TOML_FENCE_RE.finditer(text):
        body = _dedent(fence.group("body"), fence.group("indent"))
        lineno = text.count("\n", 0, fence.start()) + 2  # first line INSIDE the fence
        found.extend((lineno, body, m.group("version")) for m in _DECLARATION_RE.finditer(body))
    return found


def _declared_floors(text: str) -> list[str]:
    return [version for _, _, version in _declarations(text)]


def _declaring_docs() -> list[Path]:
    """Every Markdown page in the repository that prints a copy-pasteable floor declaration."""
    return [p for p in _repo_markdown() if _declared_floors(_text(p))]


def _posture_blocks(text: str) -> list[tuple[int, str]]:
    """``(line, block)`` for every ```toml fence of ``text`` that declares an upstream terminator."""
    found: list[tuple[int, str]] = []
    for fence in _TOML_FENCE_RE.finditer(text):
        body = _dedent(fence.group("body"), fence.group("indent"))
        if _POSTURE_RE.search(body):
            found.append((text.count("\n", 0, fence.start()) + 2, body))
    return found


def _posture_docs() -> list[Path]:
    """Every Markdown page in the repository that prints a copy-pasteable Posture-B block."""
    return [p for p in _repo_markdown() if _posture_blocks(_text(p))]


def _fence_floors(text: str) -> dict[str, str]:
    """``{'nginx': '1.2', ...}`` for whichever reference fences ``text`` carries."""
    floors = {"nginx": _nginx_floor(text), "caddy": _caddy_floor(text), "iis": _iis_floor(text)}
    return {name: value for name, value in floors.items() if value is not None}


def _backing_fences(path: Path) -> tuple[Path, dict[str, str]]:
    """The pinned fences behind ``path``'s declaration: its own, else those it links to."""
    own = _fence_floors(_text(path))
    if own:
        return path, own
    for match in _MD_LINK_RE.finditer(_text(path)):
        target = (path.parent / match.group("target")).resolve()
        if not target.is_file():
            continue
        floors = _fence_floors(_text(target))
        if floors:
            return target, floors
    raise AssertionError(
        f"{path.relative_to(_ROOT)} prints a copy-pasteable [api].proxy_tls_min_version but ships no "
        f"reverse-proxy fence and links to no document that does. The declaration is then exactly the "
        f"ASVS 12.1.1 residual — an attestation with nothing behind it, which the engine cannot check. "
        f"Either include the proxy configuration or link the page that pins it "
        f"(docs/security/OFF-LOOPBACK-DEPLOYMENT.md)."
    )


@pytest.mark.parametrize("path", _declaring_docs(), ids=lambda p: p.name)
def test_every_declared_proxy_tls_floor_is_backed_by_a_fence_that_pins_it(
    path: Path, tmp_path: Path
) -> None:
    """No document may declare a floor higher than the reference fences behind it permit.

    ``validate_proxy_tls_posture`` accepts ``"1.2"`` or ``"1.3"`` without looking at anything else —
    it validates the *string*, not the proxy. So ``proxy_tls_min_version = "1.3"`` in front of a
    fence that still permits TLS 1.2 is a false attestation the engine cannot catch, and it is
    exactly the "declaration, not enforcement" defect ASVS 12.1.1 names.

    Each declaring block is also run through the **real settings loader**, so a floor that reads
    right on the page but lands under the wrong ``[section]`` — or on a key the loader silently
    ignores — fails here rather than in an operator's start-up.
    """
    from messagefoundry.config.settings import load_settings

    source, floors = _backing_fences(path)
    weakest_fence = min(floors, key=lambda name: _as_tuple(floors[name]))
    weakest = floors[weakest_fence]
    where = f"{path.relative_to(_ROOT)} (fences: {source.relative_to(_ROOT)})"

    for lineno, block, declared in _declarations(_text(path)):
        assert _as_tuple(declared) <= _as_tuple(weakest), (
            f"FALSE ATTESTATION in {where} line {lineno}: it declares proxy_tls_min_version = "
            f"{declared!r} but the {weakest_fence} fence behind it still permits TLS {weakest}. A "
            f"browser can still negotiate {weakest} and nothing in the engine can tell. Lower the "
            f"declaration, or raise what the fence permits — in the same change."
        )
        assert declared == weakest, (
            f"{where} line {lineno} declares proxy_tls_min_version = {declared!r} while the fences "
            f"behind it permit down to TLS {weakest} ({floors}). Declare the LOWEST version the "
            f"proxy still permits: an under-claim reads as a stale copy and hides a fence that was "
            f"never narrowed."
        )

        config = tmp_path / f"line-{lineno}.toml"
        config.write_text(block, encoding="utf-8")
        settings = load_settings(config_path=config, environ={})
        assert settings.api.proxy_tls_floor_declared, (
            f"the block at {where} line {lineno} prints proxy_tls_min_version but the loader does "
            f"not see a declared floor — the key is under the wrong section, or misspelled into a "
            f"key the loader ignores. An operator copying it gets the floor-less posture back."
        )
        assert settings.api.proxy_tls_min_version == declared, (
            f"the block at {where} line {lineno} reads {declared!r} but loads as "
            f"{settings.api.proxy_tls_min_version!r}"
        )


@pytest.mark.parametrize("path", _posture_docs(), ids=lambda p: p.name)
def test_every_upstream_terminator_block_declares_the_floor_its_fences_pin(
    path: Path, tmp_path: Path
) -> None:
    """A Posture-B block with **no** floor at all is the residual in its worse form — fail it.

    The guard above keys on the *declaration*, so it can only ever catch a floor that is wrong. A
    block that declares ``tls_terminated_upstream = true`` and simply never mentions
    ``proxy_tls_min_version`` is invisible to it: no attestation to compare, no fence to compare it
    against, and — in both pages where this actually shipped — no link to the page that pins one. An
    operator copying such a block reaches Posture B with the browser-facing floor pinned nowhere and
    gets **no** signal from the engine, which is exactly what ASVS 12.1.1 asks about.

    So this derivation keys on the **posture** instead. Every such block must name the floor, that
    floor must equal the weakest reference fence behind the page (``_backing_fences`` fails a page
    that ships no fence and links to none), and the block must *load* to it. The block must also
    declare ``proxy_intra_service_auth``: it is the other half of the same startup-ladder rung (row
    1b), and a block missing it is the same copy-paste-into-a-refusal defect.
    """
    from messagefoundry.config.settings import load_settings

    blocks = _posture_blocks(_text(path))
    rel = path.relative_to(_ROOT)

    # Presence first, and for EVERY block, before resolving fences: "no floor anywhere on the page"
    # must report as the missing declaration it is, not as a missing fence.
    for lineno, block in blocks:
        assert _DECLARATION_RE.search(block) is not None, (
            f"{rel} line {lineno} prints a copy-pasteable [api].tls_terminated_upstream = true block "
            f"with NO [api].proxy_tls_min_version. In that posture the reverse proxy terminates "
            f"browser TLS and the engine observes nothing about that hop, so an operator copying "
            f"this reaches Posture B with the browser-facing TLS floor pinned NOWHERE — the ASVS "
            f"12.1.1 residual, and worse than an over-claimed floor because there is no attestation "
            f"to check. (It is also a start refusal: ladder row 1b refuses a production-PHI instance "
            f"behind a declared terminator without this key.) Declare the LOWEST version your "
            f"reference fence still permits and link the page that pins it "
            f"(docs/security/OFF-LOOPBACK-DEPLOYMENT.md)."
        )

    source, floors = _backing_fences(path)
    weakest_fence = min(floors, key=lambda name: _as_tuple(floors[name]))
    weakest = floors[weakest_fence]
    where = f"{rel} (fences: {source.relative_to(_ROOT)})"

    for lineno, block in blocks:
        config = tmp_path / f"posture-{lineno}.toml"
        config.write_text(block, encoding="utf-8")
        settings = load_settings(config_path=config, environ={})

        assert settings.api.proxy_tls_min_version == weakest, (
            f"the Posture-B block at {where} line {lineno} loads to proxy_tls_min_version="
            f"{settings.api.proxy_tls_min_version!r} while the {weakest_fence} fence behind it "
            f"permits down to TLS {weakest} ({floors}). Declare the LOWEST version the proxy still "
            f"permits, and move the fence and the declaration in the same change."
        )
        assert settings.api.proxy_intra_service_auth != "none", (
            f"the Posture-B block at {where} line {lineno} declares an upstream TLS terminator but "
            f"leaves [api].proxy_intra_service_auth undeclared. The proxy->engine hop is cleartext "
            f"in this posture and the engine cannot see how it is protected, so this is the other "
            f"half of ladder row 1b — a production-PHI instance copying this block refuses to start."
        )


def test_both_floor_derivations_still_name_every_known_posture_b_page() -> None:
    """Neither derivation may quietly go empty — an empty parametrize list reports as a SKIP.

    Both guards above are parametrized over a set derived at import time. If a page dropped its
    ``tls_terminated_upstream`` block, or dropped its ``proxy_tls_min_version`` line, the derived
    set would shrink and the corresponding guard would simply stop running on it — pytest reports a
    vanished parametrization as a skip, never a failure. That is the residual returning while the
    suite stays green, so the pages that ship a Posture-B block today are named explicitly here.

    Deleting a name is legitimate when the page genuinely stops printing the block; it just has to
    be a deliberate edit to this list rather than a silent side effect somewhere in ``docs/``.
    """
    posture = {p.name for p in _posture_docs()}
    declaring = {p.name for p in _declaring_docs()}

    assert posture >= _KNOWN_POSTURE_B_PAGES, (
        f"these pages no longer print a copy-pasteable [api].tls_terminated_upstream = true block: "
        f"{sorted(_KNOWN_POSTURE_B_PAGES - posture)}. If that is deliberate, drop the name from "
        f"_KNOWN_POSTURE_B_PAGES in the same change; if it is not, a Posture-B guard just stopped "
        f"running against an operator-facing page."
    )
    assert declaring >= _KNOWN_POSTURE_B_PAGES, (
        f"these pages print a Posture-B block but no longer declare [api].proxy_tls_min_version: "
        f"{sorted(_KNOWN_POSTURE_B_PAGES - declaring)}. Dropping the declaration is the ASVS 12.1.1 "
        f"residual coming back, not a cleanup — the floor is then pinned nowhere the operator can "
        f"read and the engine still cannot observe the browser hop."
    )


def test_the_declared_floor_is_the_one_the_runbook_fences_pin(tmp_path: Path) -> None:
    """The runbook's own engine block, loaded through the real settings loader.

    The parametrized guard above compares document text. This one proves the runbook block the
    operator copies actually *parses* to the floor of record, so a declaration that is coherent on
    the page but rejected (or silently defaulted) by the loader still fails.
    """
    from messagefoundry.config.settings import load_settings

    text = _doc()
    heading = "### The engine config beside either proxy"
    start = text.find(heading)
    assert start != -1, f"runbook section {heading!r} missing from {_DOC.name}"
    match = _TOML_FENCE_RE.search(text, start)
    assert match is not None, f"no toml block under {heading!r}"

    block = tmp_path / "messagefoundry.toml"
    block.write_text(_dedent(match.group("body"), match.group("indent")), encoding="utf-8")
    settings = load_settings(config_path=block, environ={})

    assert settings.api.proxy_tls_floor_declared, (
        "the runbook's engine block declares [api].tls_terminated_upstream but no "
        "[api].proxy_tls_min_version — an operator copying it verbatim onto a PHI instance gets a "
        "permanent floor-less startup warning (and a refusal on a non-loopback bind, ladder row 1b)"
    )
    assert settings.api.proxy_tls_min_version == _FLOOR, (
        f"the runbook's engine block loads to proxy_tls_min_version="
        f"{settings.api.proxy_tls_min_version!r}, not the floor of record {_FLOOR!r}"
    )


def test_no_floor_is_declared_where_the_coherence_guard_cannot_see_it() -> None:
    """A declaration outside a ```toml fence escapes the derivation — fail it rather than miss it.

    ``_declaring_docs`` finds declarations inside ```toml fences, because that is what an operator
    copy-pastes. A floor printed in an unmarked (or ```ini, ```conf, ...) fence is just as
    copy-pasteable and would be silently exempt from the coherence check above — the same
    one-site-missed failure this module exists to stop. Scanned repo-wide, for the same reason the
    derivations are.
    """
    stray: dict[str, list[str]] = {}
    for path in _repo_markdown():
        text = _text(path)
        anywhere = [m.group("version") for m in _DECLARATION_RE.finditer(text)]
        guarded = _declared_floors(text)
        if len(anywhere) > len(guarded):
            stray[str(path.relative_to(_ROOT))] = anywhere
    assert not stray, (
        f"proxy_tls_min_version is declared outside a ```toml fence in {stray} — the ASVS 12.1.1 "
        f"coherence guard derives its file set from ```toml fences, so that declaration ships "
        f"unchecked. Move it into a ```toml block (it is a messagefoundry.toml key)."
    )


def test_no_reference_fence_names_a_protocol_below_the_declared_floor() -> None:
    """A belt-and-braces negative: no fence may mention TLS 1.0/1.1 as something it *enables*."""
    for lang in ("nginx", "caddy"):
        body = _fence(lang)
        for token in ("TLSv1.0", "TLSv1.1", "tls1.0", "tls1.1", "TLSv1 ", "SSLv3"):
            assert token not in body, (
                f"the {lang} reference fence names {token!r} — every reference config must sit at or "
                f"above the declared floor of TLS {_FLOOR}"
            )
