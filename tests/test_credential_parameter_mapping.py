# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A credential factory PARAMETER must land on a SETTING name the redactor covers (BACKLOG #1208).

THE BOUNDARY, and why it needed its own guard. A connector factory takes a credential parameter and
emits it under a DIFFERENT setting name. Every redaction control operates on the SETTING name. Nothing
asserted the two agree, so a rename silently moved a credential outside the control's domain. Three
measured instances of that one shape, all now closed:

===================================  ==========================  ============================
factory                              PARAMETER (classified)      emitted SETTING (was not)
===================================  ==========================  ============================
``with_signing``                     ``private_key``             ``sign_private_key``
``with_signing``                     ``private_key_password``    ``sign_private_key_password``
``Rest``                             ``proxy``                   ``proxy_url``
===================================  ==========================  ============================

``_is_secret_setting("private_key")`` was True and ``_is_secret_setting("sign_private_key")`` was
False: the parameter was covered and the setting it became was not. ``proxy`` -> ``proxy_url`` crosses
the same boundary and is harmless only because the URL-userinfo rule happens to cover the destination,
which is luck rather than design. THIS FILE MAKES IT DESIGN.

WHY THE TWO EXISTING GUARDS CANNOT SEE IT.

* ``test_every_credential_shaped_factory_param_is_classified`` reads PARAMETER names -- one abstraction
  level away from where redaction operates. That is exactly how the ``with_signing`` rename walked
  through it.
* ``tests/test_connection_factory_redaction_domain.py`` reads EMITTED settings end to end and proves the
  OUTCOME per factory: nothing recognisably secret survives. It does not prove the MAPPING. A parameter
  the factory drops, renames into a container, or folds into a composed string emits no sentinel at all,
  and "no sentinel survived redaction" is then true for the least interesting reason.

THIS IS NOT A FOURTH NAME LIST, and that is the whole point of the item. ``private_key`` and
``sign_private_key`` are different strings, so any name-to-name comparison has to be TAUGHT each rename
and therefore cannot catch the next one. **The mapping is discovered by following the VALUE**: inject a
unique sentinel into ONE parameter, call the factory, and search the emitted settings for it. The
destination key is whatever the sentinel is found under -- read off the running code, never declared
here. Only then is the real redactor asked about that destination.

WHAT EACH PARAMETER MUST DO, one of:

1. land in at least one setting whose name the redactor MASKS (the credential case), or
2. land in at least one setting whose name the URL-userinfo rule covers (the URL-bearing case), or
3. land in a destination declared in :data:`NON_MATERIAL_DESTINATIONS` -- a key that carries a NAME, a
   PATH or an IDENTIFIER rather than material, WITH the reason, or
4. reach no setting at all, and be declared in :data:`NON_EMITTING` WITH the reason.

A parameter that cannot be probed at all is a FAILURE, never a skip: an unbuildable factory is a hole
in the domain, and a hole that reports "clean" is the defect this family keeps recurring as.

THE DECLARED TABLES CANNOT GO STALE. ``test_no_declared_exemption_is_stale`` fails when an entry in
either table is not actually reached by the probe. An allowlist nobody re-derives is the same defect one
level up -- a guard closing over an enumeration that stopped matching the code.

MEASURED 2026-08-10, by reverting the shipped redaction to each pre-fix state in turn and watching what
this file does. 58 parameters probed across the spec-returning domain:

===============================================  ==================  ==============================
reverted to                                      goes RED            still GREEN
===============================================  ==================  ==============================
shipped code (control)                            0                   58
pre-#1106 (``sign_private_key`` unclassified)     2                   56
pre-#1207 (no URL-userinfo mask)                 10                   48
shipped code again (control)                      0                   58
===============================================  ==================  ==============================

**The red is SPECIFIC, not uniform, and that is the result worth having.** Pre-#1106 turns exactly the
two renamed ``with_signing`` parameters red and leaves 56 passing -- so this file locates the layer that
does the work rather than merely reacting to it. Pre-#1207 turns exactly the ten URL-bearing parameters
red. A control that reddened on all 58 in both cases would have looked stronger and taught nothing.

WHAT IT ADDS OVER THE SIBLING, measured the same day rather than argued. De-classifying five credential
settings that reach connectors through an ``env()``-only refusal or a coupled argument --
``intake_api_key``, ``intake_api_key_next``, ``credential_password``, ``ws_password``,
``client_key_password`` -- turns **this** file red on all five and
``test_connection_factory_redaction_domain.py`` red on **none**. That sibling drops a connector's
credential arguments when the connector refuses to be built with them, so those five surfaces were
inside its stated domain and outside what it could actually see.
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any, NamedTuple

import pytest

import messagefoundry
from messagefoundry.config.wiring import redacted_settings
from tests.test_connection_factory_redaction_domain import (
    _factories_returning_a_spec,
    _is_credential_param,
)

# ---------------------------------------------------------------------------------------------------
# Sentinels. Fixed width with a terminator so no sentinel can be a PREFIX of another -- the first draft
# of this probe injected every parameter at once and reported `private_key` as landing in
# `sign_private_key_password`, because its sentinel was a prefix of the password parameter's. One
# parameter is injected per probe now, which removes the ambiguity at the source rather than papering
# over it, and the fixed width keeps that true if the probe is ever widened again.
# ---------------------------------------------------------------------------------------------------
_SENTINEL_N = 0


def _next_sentinel() -> str:
    global _SENTINEL_N
    _SENTINEL_N += 1
    return f"MFMAP{_SENTINEL_N:04d}ZZ"


#: A SOAP body-secret placeholder must match ``^[A-Za-z0-9_.@-]{16,64}$``; anything shorter is refused.
def _placeholder_sentinel(sentinel: str) -> str:
    return f"{sentinel}{'0' * (16 - len(sentinel))}" if len(sentinel) < 16 else sentinel


class Landing(NamedTuple):
    """Where one parameter's sentinel was actually found."""

    factory: str
    param: str
    kind: str  # "credential" | "url"
    form: str  # "inline" | "env()"
    keys: tuple[str, ...]


# ---------------------------------------------------------------------------------------------------
# Declared tables. Both are asserted REACHED, so neither can quietly stop matching the code.
# ---------------------------------------------------------------------------------------------------

#: Destination setting keys that a credential-shaped PARAMETER legitimately lands on unredacted,
#: because the key carries a NAME, a PATH or an IDENTIFIER and not material. Each needs a reason.
NON_MATERIAL_DESTINATIONS: dict[str, str] = {
    "odbc_password_key": (
        "the NAME of the ODBC keyword to put the password under (default 'PWD'), not the password -- "
        "naming indirection. Masking it would hide which keyword an operator has to look at"
    ),
    "odbc_user_key": "the NAME of the ODBC user keyword (default 'UID'), not the user",
    "signing_key": (
        "a PATH to the sender's PEM/DER key, not the material; transports/direct.py _read_file()s it. "
        "The engine classifies signing_key_password and NOT signing_key deliberately"
    ),
    "intake_api_key_header": (
        "the NAME of the header the intake credential arrives in (default 'x-api-key'). The "
        "credential itself is intake_api_key, which IS masked -- and is env()-only besides"
    ),
    "credential_domain": (
        "an AD domain name, documented non-secret in wiring.py: it names the directory the share "
        "identity belongs to. credential_username and credential_password are both masked"
    ),
    "body_secret_tokens": (
        "SOAP body-secret PLACEHOLDER tokens (ADR 0015 amendment). Public BY CONTRACT -- the token "
        "sits in committed Handler source and the transport swaps the real env() credential in at "
        "send time. The paired body_secret_value_<i> IS masked"
    ),
    "proxy_no_proxy": (
        "hostname EXCLUSIONS -- the hosts to bypass the proxy for. Public by nature, and not a URL: "
        "it is selected by the URL suffix rule only because the name ends in 'proxy'. Masking it "
        "would hide routing configuration an operator has to audit"
    ),
}

#: Parameters whose sentinel reaches NO setting, with the reason. Empty today and asserted so: every
#: credential-shaped parameter on every factory currently lands somewhere. The table exists because
#: "reached nothing" is the interesting outcome the OUTCOME-level guard cannot distinguish from
#: "reached something safe", and it must have a stated home when it happens rather than passing quietly.
NON_EMITTING: dict[tuple[str, str], str] = {}

#: Arguments a factory REQUIRES alongside the parameter under test, because it refuses the parameter
#: on its own. Connector-specific and therefore declared with a reason rather than inferred -- but the
#: alternative is dropping the parameter, and a probe that drops what it cannot build is a guard that
#: examined nothing.
ENABLING_ARGUMENTS: dict[tuple[str, str], dict[str, Any]] = {
    ("Http", "intake_api_key"): {"intake_auth": "api_key"},
    ("Http", "intake_api_key_next"): {
        "intake_auth": "api_key",
        "intake_api_key": messagefoundry.env("probe_primary_key"),
    },
    ("Http", "intake_api_key_header"): {
        "intake_auth": "api_key",
        "intake_api_key": messagefoundry.env("probe_primary_key"),
    },
    ("File", "credential_username"): {"credential_password": messagefoundry.env("probe_share_pw")},
    ("File", "credential_password"): {
        "credential_username": messagefoundry.env("probe_share_user")
    },
    ("File", "credential_domain"): {
        "credential_username": messagefoundry.env("probe_share_user"),
        "credential_password": messagefoundry.env("probe_share_pw"),
    },
    ("Soap", "basic_password"): {"basic_user": "probe-user"},
    ("Soap", "ws_password"): {"ws_username": "probe-user"},
    ("Soap", "proxy_password"): {"proxy": "http://proxy.invalid:8080", "proxy_user": "probe-user"},
    ("Rest", "proxy_password"): {"proxy": "http://proxy.invalid:8080", "proxy_user": "probe-user"},
    ("FHIR", "proxy_password"): {"proxy": "http://proxy.invalid:8080", "proxy_user": "probe-user"},
    ("DICOMweb", "proxy_password"): {
        "proxy": "http://proxy.invalid:8080",
        "proxy_user": "probe-user",
    },
}

#: Parameters whose accepted SHAPE is not a bare string, so a plain sentinel cannot be injected. The
#: builder still follows the value; only the wrapper is declared.
SHAPED_INJECTION: dict[tuple[str, str], Any] = {
    ("Soap", "body_secrets"): lambda s: {_placeholder_sentinel(s): messagefoundry.env(s.lower())},
}

#: Suffixes that make a parameter URL-BEARING: its value may carry ``user:password@`` userinfo, so the
#: destination must be a key the URL rule covers. A SUFFIX rule, not an enumeration -- and its coverage
#: is checked against the running code by
#: :func:`test_the_url_suffix_rule_selects_every_parameter_that_lands_in_a_url_setting`.
URL_BEARING_SUFFIXES = ("url", "uri", "endpoint", "proxy")

#: What the redactor's own URL rule covers. Read here only to CHECK the suffix rule above against the
#: code; the mapping itself is still discovered by following the sentinel.
_URL_DESTINATION_SUFFIXES = ("url", "_uri", "endpoint", "_endpoint")


def _is_url_bearing_param(name: str) -> bool:
    low = name.lower()
    return low.endswith(URL_BEARING_SUFFIXES) and not _is_credential_param(name)


def _resolve(mod: str, name: str) -> Any:
    fn = getattr(importlib.import_module(mod), name, None)
    return fn if callable(fn) else None


def _takes_a_spec(fn: Any) -> bool:
    params = list(inspect.signature(fn).parameters.values())
    return bool(params) and params[0].name == "spec"


def _filler(p: inspect.Parameter) -> Any:
    """Any plausible value for a REQUIRED non-credential argument -- it keeps the call alive and is
    never the thing under assertion."""
    ann = str(p.annotation)
    if "url" in p.name.lower():
        return "https://example.invalid/token"
    if "int" in ann and "str" not in ann:
        return 2575
    if "statement" in p.name:
        return "SELECT 1"
    return "x"


def _usable_params(fn: Any) -> list[inspect.Parameter]:
    params = list(inspect.signature(fn).parameters.values())
    rest = params[1:] if _takes_a_spec(fn) else params
    return [p for p in rest if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)]


def _find_sentinel(settings: dict[str, Any], sentinel: str) -> tuple[str, ...]:
    """Every settings key whose value carries the sentinel, at any depth.

    ``str(value)`` covers the nested cases the flat scan would miss -- a dict, a list, and an ``EnvRef``
    whose ``key`` IS the sentinel when the factory demanded ``env()``.
    """
    low = sentinel.lower()
    return tuple(k for k, v in settings.items() if low in str(v).lower())


class ProbeResult(NamedTuple):
    landing: Landing | None
    refused_inline: bool
    error: str | None


def _probe(factory: str, fn: Any, p: inspect.Parameter, kind: str) -> ProbeResult:
    """Inject ONE sentinel into ONE parameter and report where it landed."""
    sentinel = _next_sentinel()
    shaper = SHAPED_INJECTION.get((factory, p.name))
    if shaper is not None:
        injected: Any = shaper(sentinel)
    elif kind == "url":
        injected = f"https://probeuser:{sentinel}@proxy.invalid:8080/path"
    else:
        injected = sentinel

    kwargs: dict[str, Any] = {
        q.name: _filler(q) for q in _usable_params(fn) if q.default is inspect.Parameter.empty
    }
    kwargs.update(ENABLING_ARGUMENTS.get((factory, p.name), {}))
    kwargs[p.name] = injected
    base = messagefoundry.Rest(url="https://example.invalid/endpoint")
    decorator = _takes_a_spec(fn)

    def build(kw: dict[str, Any]) -> Any:
        return fn(base, **kw) if decorator else fn(**kw)

    refused = False
    try:
        spec = build(kwargs)
        form = "inline"
    except Exception as inline_exc:  # noqa: BLE001 - the refusal message IS the signal here
        # THE CONNECTOR REFUSES AN INLINE CREDENTIAL AND DEMANDS env(). That is the STRONGER control --
        # the value never resolves into settings, so no serializer can leak it. The MAPPING question
        # survives it: the EnvRef's key is the sentinel, so the destination is still discoverable, and
        # the destination is what this file asserts about.
        refused = True
        kwargs[p.name] = messagefoundry.env(sentinel.lower())
        try:
            spec = build(kwargs)
            form = "env()"
        except Exception as env_exc:  # noqa: BLE001
            return ProbeResult(
                None,
                refused,
                f"inline: {type(inline_exc).__name__}: {inline_exc}; "
                f"env(): {type(env_exc).__name__}: {env_exc}",
            )

    keys = _find_sentinel(dict(spec.settings), sentinel)
    return ProbeResult(Landing(factory, p.name, kind, form, keys), refused, None)


def _collect() -> tuple[list[Landing], list[str], set[str]]:
    """Probe every credential- and URL-bearing parameter of every spec-returning factory."""
    landings: list[Landing] = []
    errors: list[str] = []
    refused: set[str] = set()
    for mod, name in _factories_returning_a_spec():
        fn = _resolve(mod, name)
        if fn is None:  # pragma: no cover - the sibling's domain test fails first if this happens
            errors.append(f"{mod}.{name}: not importable")
            continue
        for p in _usable_params(fn):
            kind = (
                "credential"
                if _is_credential_param(p.name)
                else "url"
                if _is_url_bearing_param(p.name)
                else None
            )
            if kind is None:
                continue
            result = _probe(name, fn, p, kind)
            if result.refused_inline:
                refused.add(f"{name}.{p.name}")
            if result.landing is None:
                errors.append(f"{name}.{p.name} could not be built -- {result.error}")
                continue
            landings.append(result.landing)
    return landings, errors, refused


LANDINGS, PROBE_ERRORS, REFUSED_INLINE = _collect()

#: The credential-shaped landings, as pytest ids.
_IDS = [f"{ln.factory}.{ln.param}" for ln in LANDINGS]


def test_every_credential_and_url_parameter_was_probed() -> None:
    """LIVENESS, and it reports WHAT it scanned rather than only a count.

    A probe that built nothing would make every parametrised assertion below vacuous, and an
    unbuildable factory is a hole in the domain -- never a skip.
    """
    print(
        f"[1208] probed {len(LANDINGS)} parameters across {len({ln.factory for ln in LANDINGS})} "
        f"factories; {len(REFUSED_INLINE)} refused an inline credential and were followed via env()"
    )
    for ln in sorted(LANDINGS):
        print(
            f"[1208]   {ln.factory}.{ln.param} ({ln.kind}, {ln.form}) -> {list(ln.keys) or 'NOTHING'}"
        )
    assert not PROBE_ERRORS, (
        "these parameters could not be probed, so nothing here covers them:\n  "
        + "\n  ".join(PROBE_ERRORS)
        + "\nAdd the arguments the factory couples them to in ENABLING_ARGUMENTS (with the reason), or "
        "the shape it demands in SHAPED_INJECTION. Do NOT drop the parameter: a probe that skips what "
        "it cannot build is a guard that examined nothing."
    )
    assert LANDINGS, "the probe found no credential- or URL-bearing parameters at all"


def test_the_domain_is_every_spec_returning_factory() -> None:
    """The domain is DERIVED, and derived ONCE.

    It reuses ``_factories_returning_a_spec`` rather than re-walking the AST: a second derivation of
    the same population is free to drift from the first, which is the defect one level up. 23 when
    BACKLOG #1206 was fixed, and this asserts AT LEAST that -- a shrinking domain is how this class
    recurs.
    """
    discovered = {n for _, n in _factories_returning_a_spec()}
    print(f"[1208] domain = {len(discovered)} spec-returning factories: {sorted(discovered)}")
    assert len(discovered) >= 23, (
        f"the spec-returning domain shrank to {len(discovered)}; it was 23 when #1206 was fixed"
    )
    probed = {ln.factory for ln in LANDINGS}
    unprobed = discovered - probed
    # A factory with no credential- or URL-bearing parameter legitimately contributes no landing.
    for name in sorted(unprobed):
        mod = next(m for m, n in _factories_returning_a_spec() if n == name)
        fn = _resolve(mod, name)
        assert fn is not None
        interesting = [
            p.name
            for p in _usable_params(fn)
            if _is_credential_param(p.name) or _is_url_bearing_param(p.name)
        ]
        assert not interesting, (
            f"{name} has credential/URL parameters {interesting} but produced no landing -- the probe "
            "silently dropped it"
        )


@pytest.mark.parametrize("landing", LANDINGS, ids=_IDS)
def test_a_credential_parameter_lands_on_a_setting_the_redactor_covers(landing: Landing) -> None:
    """THE ASSERTION. The destination is read off the running code; the verdict comes from the real
    redactor.

    Measured failure this catches, at engine ``64f6e178``: ``with_signing``'s ``private_key`` parameter
    landed on ``sign_private_key``, and ``redacted_settings`` returned it VERBATIM through
    ``GET /connections/{name}/metadata`` behind ``MONITORING_READ`` alone.
    """
    if not landing.keys:
        reason = NON_EMITTING.get((landing.factory, landing.param))
        assert reason, (
            f"{landing.factory}.{landing.param} reaches NO setting. It was consumed, composed into "
            "another value, or dropped -- each of those needs a stated reason rather than silence, "
            "because the outcome-level guard cannot tell them apart from 'safely redacted'. Declare it "
            "in NON_EMITTING with the reason, or fix the factory."
        )
        return

    probe = _next_sentinel()
    unmasked: list[str] = []
    for key in landing.keys:
        if key in NON_MATERIAL_DESTINATIONS:
            continue
        # Ask the REAL control about the destination the sentinel actually reached. For a credential
        # parameter the whole value is secret; for a URL-bearing one only the userinfo is, and masking
        # the whole URL would destroy the operator's view rather than protect it.
        value = f"https://probeuser:{probe}@host.invalid/p" if landing.kind == "url" else probe
        if probe in str(redacted_settings({key: value}).get(key)):
            unmasked.append(key)

    assert not unmasked, (
        f"{landing.factory}.{landing.param} ({landing.kind}) lands on {unmasked}, and a credential "
        f"placed under {'/'.join(unmasked)} survives redacted_settings. The PARAMETER may already be "
        "classified under a DIFFERENT name -- that rename IS the defect this file exists for (BACKLOG "
        "#1208). Classify the destination in config/wiring.py (_SECRET_SETTING_KEYS / "
        "_is_secret_setting), or declare it in NON_MATERIAL_DESTINATIONS here WITH the reason it "
        "carries a name, a path or an identifier rather than material."
    )


@pytest.mark.parametrize(
    "landing",
    [ln for ln in LANDINGS if ln.kind == "url"],
    ids=[f"{ln.factory}.{ln.param}" for ln in LANDINGS if ln.kind == "url"],
)
def test_masking_a_url_destination_does_not_destroy_the_operator_view(landing: Landing) -> None:
    """THE ASYMMETRY on the URL arm, and it is not decoration.

    A redactor that replaced every URL with ``***`` would satisfy the assertion above while silently
    removing the account and host an operator needs to diagnose a connection -- a loss nothing would
    report. The control must fail for the userinfo shape and KEEP PASSING for everything beside it.
    """
    probe = _next_sentinel()
    for key in landing.keys:
        if key in NON_MATERIAL_DESTINATIONS:
            continue
        out = str(
            redacted_settings({key: f"https://probeuser:{probe}@host.invalid/p?q=1"}).get(key)
        )
        assert "probeuser" in out and "host.invalid/p?q=1" in out, (
            f"{key} lost the user, host or path: {out!r}. Only the secret is supposed to be removed."
        )
        plain = str(redacted_settings({key: "https://plain.invalid/path?q=1"}).get(key))
        assert plain == "https://plain.invalid/path?q=1", (
            f"{key} rewrote a URL with no userinfo to {plain!r} -- that mangles ordinary configuration"
        )


def test_the_url_suffix_rule_selects_every_parameter_that_lands_in_a_url_setting() -> None:
    """The suffix rule's OWN coverage, checked against the running code rather than asserted.

    ``URL_BEARING_SUFFIXES`` is a shape rule, and a shape rule can still miss a parameter. The oracle is
    the destination: any parameter whose value lands on a setting the redactor's URL rule covers must
    have been selected as URL-bearing, or its userinfo was never checked by anything.
    """
    selected = {(ln.factory, ln.param) for ln in LANDINGS if ln.kind == "url"}
    missed: list[str] = []
    for mod, name in _factories_returning_a_spec():
        fn = _resolve(mod, name)
        if fn is None:  # pragma: no cover
            continue
        for p in _usable_params(fn):
            if (name, p.name) in selected or _is_credential_param(p.name):
                continue
            result = _probe(name, fn, p, "url")
            if result.landing is None:
                continue  # the parameter refuses a URL outright; it cannot carry userinfo
            for key in result.landing.keys:
                if key.lower().endswith(_URL_DESTINATION_SUFFIXES):
                    missed.append(f"{name}.{p.name} -> {key}")
    print(f"[1208] URL-bearing rule selected {len(selected)} parameters: {sorted(selected)}")
    assert not missed, (
        f"these parameters land on a URL-shaped setting but the suffix rule did not select them, so "
        f"nothing checked their userinfo: {missed}. Widen URL_BEARING_SUFFIXES."
    )


def test_at_least_one_connector_still_refuses_an_inline_credential() -> None:
    """The env()-only refusal is a STRONGER control than redaction and it is asserted, not assumed.

    ``Http`` and ``File`` refuse an inline credential outright, so the value never resolves into
    settings at all. If this set empties, either the refusals were removed (a real regression) or the
    probe stopped detecting them -- and a green would prove neither.
    """
    print(f"[1208] parameters that refuse an inline credential: {sorted(REFUSED_INLINE)}")
    assert REFUSED_INLINE, (
        "no factory refused an inline credential. Either the env()-only refusals were removed, or the "
        "probe stopped detecting them."
    )


def test_no_declared_exemption_is_stale() -> None:
    """A guard that closes over an enumeration which stopped matching the code is this defect one level
    up. Every declared exemption must be REACHED by the probe."""
    reached_keys = {key for ln in LANDINGS for key in ln.keys}
    stale_destinations = sorted(set(NON_MATERIAL_DESTINATIONS) - reached_keys)
    assert not stale_destinations, (
        f"NON_MATERIAL_DESTINATIONS declares {stale_destinations}, which no probed parameter reaches. "
        "Either the factory changed and the entry is dead, or the probe stopped reaching it. Remove "
        "the entry only after confirming which."
    )
    empty_landings = {(ln.factory, ln.param) for ln in LANDINGS if not ln.keys}
    stale_non_emitting = sorted(set(NON_EMITTING) - empty_landings)
    assert not stale_non_emitting, (
        f"NON_EMITTING declares {stale_non_emitting}, which now DOES reach a setting. Delete the entry "
        "-- the parameter is covered by the mapping assertion again."
    )
    for reason in list(NON_MATERIAL_DESTINATIONS.values()) + list(NON_EMITTING.values()):
        assert len(reason) > 20, "every exemption needs a real reason, not a placeholder"


def test_the_mapping_assertion_goes_red_on_a_renamed_destination() -> None:
    """NEGATIVE CONTROL. A gate that has never been red is a claim, not a control.

    ``with_signing`` is rebuilt here in miniature: a factory that takes a classified credential
    parameter and emits it under an UNclassified name. The probe must find the destination and the
    redactor must be seen failing to mask it -- which is the exact shape of the three closed instances.
    """
    sentinel = _next_sentinel()

    def _renaming_factory(*, private_key: str) -> Any:
        spec = messagefoundry.Rest(url="https://example.invalid/x")
        # A destination the redactor does not classify -- `sign_private_key` before BACKLOG #1106.
        spec.settings["vendor_signing_material"] = private_key
        return spec

    spec = _renaming_factory(private_key=sentinel)
    keys = _find_sentinel(dict(spec.settings), sentinel)
    assert keys == ("vendor_signing_material",), keys
    # The verdict the parametrised assertion applies, run against this destination.
    probe = _next_sentinel()
    assert probe in str(redacted_settings({keys[0]: probe}).get(keys[0])), (
        "the control cannot see an unclassified destination, so its green above proves nothing"
    )
    # ASYMMETRY: the SAME verdict on a classified destination must stay clean, or the control is just
    # failing on everything and cannot tell you which layer does the work.
    assert probe not in str(redacted_settings({"sign_private_key": probe}).get("sign_private_key"))
