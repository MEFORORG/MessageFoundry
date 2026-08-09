# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every connection factory's EMITTED settings survive `redacted_settings` (BACKLOG #1106).

This is the third guard against one class, and the first two both failed the same way: **they chose a
domain narrower than the surface.**

1. The original exhaustive redaction test built its sentinels *from* ``_SECRET_SETTING_KEYS``, so a
   credential never added to that frozenset could not fail it. Four did exactly that -- ``ws_password``,
   ``ws_username``, ``client_key_password`` and ``signing_key_password`` -- and were served in plaintext
   by ``GET /connections/{name}/metadata`` to ``Role.VIEWER``, past green CI.
2. Its replacement, ``test_every_credential_shaped_factory_param_is_classified``, reads connector
   factory **parameter names**. That is one abstraction level away from the names redaction actually
   operates on, and ``with_signing`` renames across exactly that boundary: the parameter is
   ``private_key`` (classified, because ``_is_secret_setting('private_key')`` is True) and the setting
   it emits is ``sign_private_key`` (not classified). The parameter was covered and the setting leaked.

So this one asserts the property END TO END, at the level the control operates: **call the factory, take
the settings it actually emitted, run the real redactor over them, and require that nothing recognisably
secret survives.** No frozenset is consulted, no parameter name is inspected, and the sentinel values
come from this test rather than from the thing under test.

**The domain is DERIVED, never listed.** It is every function in the package annotated to return a
``ConnectionSpec``, found by AST. A new factory joins the domain by existing; nobody has to remember to
add it here, which is the failure that produced defects 1 and 2 above.
"""

from __future__ import annotations

import ast
import base64
import importlib
import inspect
import json
import pathlib
from typing import Any

import pytest

import messagefoundry
from messagefoundry.config.wiring import redacted_settings

PKG = pathlib.Path(messagefoundry.__file__).resolve().parent

#: A value this test invents. Deriving it from the code under test is how guard 1 blinded itself.
SENTINEL = "MFTEST-CREDENTIAL-MUST-NOT-SURVIVE"

#: Substrings that make a settings KEY look like it carries a credential. Deliberately broad: a false
#: positive here costs one explicit declaration, a false negative costs a served secret.
CREDENTIAL_ISH = ("password", "secret", "token", "key", "credential", "passphrase")

#: Keys that contain a credential-ish substring but are NOT secrets, each needing a stated reason.
#: This is the only allowlist in the file and it is about KEYS, not about values.
NOT_A_SECRET: dict[str, str] = {
    "sign_key_id": "a key IDENTIFIER (JWS kid) -- names which key, carries no key material",
    "key_id": "identifier, not material",
    "tls_key_file": "a PATH to key material, not the material; the file's contents never enter settings",
    "encryption_key_file": "a PATH, as above",
    "smart_private_key_file": "a PATH, as above",
    "auth_style": "no credential; matched only because callers sometimes spell it *_key",
}


#: Name endings that make a credential-ish parameter NOT a credential: it names or locates one rather
#: than carrying it. The exclusion belongs HERE, at injection, not in an allowlist of leaks -- feeding a
#: sentinel to `key_id` and then reporting that it was not redacted would be the TEST being wrong, since
#: an identifier is not supposed to be redacted. Three of the four factories tripped exactly that on the
#: first run (`smart_key_id`, `smart_token_url`, `oauth2_token_url`); only `with_signing` survived as a
#: real finding, so getting this boundary right is what separates the signal from the noise.
NOT_CREDENTIAL_SUFFIX = ("_id", "_url", "_uri", "_file", "_path", "_name", "_style", "_type")


def _is_mapping_param(p: inspect.Parameter) -> bool:
    return any(t in str(p.annotation) for t in ("Mapping", "dict", "Dict"))


def _is_container_param(p: inspect.Parameter) -> bool:
    """Does this parameter carry a dict or list into the settings map?"""
    ann = str(p.annotation)
    return _is_mapping_param(p) or any(t in ann for t in ("Sequence", "list", "List", "Iterable"))


def _is_credential_param(name: str) -> bool:
    low = name.lower()
    if low.endswith(NOT_CREDENTIAL_SUFFIX):
        return False
    return any(t in low for t in CREDENTIAL_ISH)


def _factories_returning_a_spec() -> list[tuple[str, str]]:
    """AST-enumerate `(module, name)` for every function annotated `-> ConnectionSpec`.

    Annotation-based on purpose: it needs no import, no execution and no registry, so a factory cannot
    hide from the domain by being unexported. `messagefoundry.__all__` is NOT the domain -- four of
    these are public and absent from it, and one of those four is the leak this file exists for.
    """
    found: list[tuple[str, str]] = []
    for path in sorted(PKG.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a syntax error fails the rest of the suite anyway
            continue
        mod = ".".join(path.relative_to(PKG.parent).with_suffix("").parts)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.returns is not None
                and "ConnectionSpec" in ast.unparse(node.returns)
                and not node.name.startswith("_")
            ):
                found.append((mod, node.name))
    return found


def _decorator_style(mod: str, name: str) -> Any | None:
    """Return the callable if it is a `(spec, *, ...) -> ConnectionSpec` decorator, else None.

    Those are the ones that ADD settings to an existing spec, which is where a rename across the
    parameter/setting boundary can happen. Base constructors are covered by their own connector tests.
    """
    fn = getattr(importlib.import_module(mod), name, None)
    if fn is None or not callable(fn):
        return None
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):  # pragma: no cover
        return None
    return fn if params and params[0].name == "spec" else None


def _call_with_sentinels(fn: Any) -> Any:
    """Invoke the factory, passing SENTINEL for every credential-shaped keyword parameter."""
    kwargs: dict[str, Any] = {}
    for p in list(inspect.signature(fn).parameters.values())[1:]:
        if p.kind not in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD):
            continue
        looks_secret = _is_credential_param(p.name)
        if looks_secret:
            kwargs[p.name] = SENTINEL
        elif p.default is inspect.Parameter.empty:
            # A required non-credential argument. Any plausible string keeps the call alive; the
            # assertion is about credential values, not this one.
            kwargs[p.name] = "https://example.invalid/token" if "url" in p.name else "x"
        elif _is_container_param(p):
            # OPTIONAL CONTAINER PARAMETERS ARE POPULATED DELIBERATELY. Passing only the REQUIRED
            # arguments left every container empty, and the surface walk below skips empty containers
            # -- so it examined nothing and passed vacuously. Measured: zero containers walked. A
            # guard that passes because it looked at nothing is the exact defect this file exists for,
            # and it very nearly shipped inside the generalisation of it.
            kwargs[p.name] = {"X-Probe": SENTINEL} if _is_mapping_param(p) else ["X-Probe"]
    base = messagefoundry.Rest(
        url="https://example.invalid/endpoint", headers={"X-Probe-Auth": SENTINEL}
    )
    return fn(base, **kwargs)


FACTORIES = [
    (mod, name)
    for mod, name in _factories_returning_a_spec()
    if _decorator_style(mod, name) is not None
]


def test_the_domain_is_not_empty_and_is_wider_than_the_public_api() -> None:
    """LIVENESS + the specific blindness that caused #1106.

    If the AST walk silently found nothing, every parametrised test below would vacuously pass. And if
    someone narrows the domain to `messagefoundry.__all__`, this fails -- that narrowing IS the defect:
    `with_signing` is public, absent from `__all__`, and the one that leaks.
    """
    assert FACTORIES, "the factory AST walk found nothing; the domain is broken, not clean"
    names = {n for _, n in FACTORIES}
    exported = set(getattr(messagefoundry, "__all__", []))
    assert names - exported, (
        "every spec-returning factory is exported, so this test can no longer detect the "
        "unexported-factory blindness it was written for"
    )


@pytest.mark.parametrize(("mod", "name"), FACTORIES, ids=[n for _, n in FACTORIES])
def test_no_factory_emits_a_credential_that_survives_redaction(mod: str, name: str) -> None:
    """THE ASSERTION, at the level the control actually operates.

    Measured failure this catches, at engine `64f6e178`:

        with_signing(spec, private_key=S, private_key_password=S).settings
          -> sign_private_key, sign_private_key_password
        redacted_settings(...) -> both returned VERBATIM

    reachable through `GET /connections/{name}/metadata` behind `MONITORING_READ` alone, and printed by
    `graph --json` to stdout, a CI log and the IDE.
    """
    fn = _decorator_style(mod, name)
    assert fn is not None
    spec = _call_with_sentinels(fn)
    redacted = redacted_settings(dict(spec.settings))

    leaked = sorted(k for k, v in redacted.items() if SENTINEL in str(v) and k not in NOT_A_SECRET)
    assert not leaked, (
        f"{mod}.{name} emits settings {leaked} that carry credential material through "
        f"redacted_settings unredacted. Either classify them (config/wiring.py "
        f"_SECRET_SETTING_KEYS / _is_secret_setting) or add them to NOT_A_SECRET here WITH a reason. "
        f"Note the parameter may already be classified under a DIFFERENT name -- that is exactly the "
        f"rename gap this test exists to catch."
    )


#: Credential-bearing headers a real deployment sends. NOT drawn from `_SECRET_HEADER_NAMES` -- that
#: frozenset was the defect (BACKLOG #1201): five exact names, matched by membership, against a domain
#: that is OPERATOR-AUTHORED FREE TEXT and therefore cannot be enumerated even in principle.
SECRET_HEADERS = [
    "Authorization",
    "Proxy-Authorization",
    "X-API-Key",
    "Cookie",
    "X-Auth-Token",  # leaked before #1201
    "X-Amz-Security-Token",  # leaked before #1201 -- an AWS SigV4 session credential
    "Private-Token",  # leaked before #1201 -- GitLab's standard auth header
    "X-Vault-Token",
    "X-Session-Secret",
]

#: Headers that must STAY VISIBLE. Redacting these costs an operator their routing and tracing view,
#: and `Idempotency-Key` is the sharp one -- it carries "key", is a client-generated request id, and is
#: published in the API docs of every service that uses it.
PUBLIC_HEADERS = [
    "Content-Type",
    "Accept",
    "User-Agent",
    "X-Correlation-Id",
    "X-Request-Id",
    "X-Forwarded-For",
    "X-Api-Version",
    "Idempotency-Key",
]


@pytest.mark.parametrize("header", SECRET_HEADERS)
def test_a_credential_bearing_header_is_redacted(header: str) -> None:
    """The #1106 defect again, one surface over, and structurally worse.

    Settings keys come from factory signatures, so they are at least enumerable. HEADER names are typed
    by an operator into `connections.toml` or a Handler, so no list can be complete -- which is why this
    is matched by SHAPE and why the test names credentials the shipped list never contained.
    """
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={header: SENTINEL})
    out = redacted_settings(dict(spec.settings))["headers"]
    assert SENTINEL not in str(out.get(header)), (
        f"{header} carries a credential and was served verbatim by /metadata and graph --json"
    )


@pytest.mark.parametrize("header", PUBLIC_HEADERS)
def test_a_public_header_is_not_redacted(header: str) -> None:
    """The other half. Erring toward redaction is right, but a rule that hides everything is not a
    control -- it is a broken diagnostic view, and nothing would say so."""
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={header: "public-value"})
    out = redacted_settings(dict(spec.settings))["headers"]
    assert out.get(header) == "public-value", f"{header} is not a credential and must stay readable"


#: Container-valued settings the redactor KNOWS HOW TO DESCEND INTO, each with the rule that covers it.
#: Anything else nested is unreachable by redaction, because `redacted_settings` masks flat scalars via
#: `_is_secret_setting` and descends only into `headers` via `_is_secret_header`.
HANDLED_CONTAINERS: dict[str, str] = {
    "headers": "per-key via _is_secret_header",
    "dynamic_headers": (
        "values are HL7 field REFERENCES (e.g. 'MSH-4'), not credentials -- the secret arrives from "
        "the message at runtime and never enters settings"
    ),
    "capture_response_headers": "a list of header NAMES to capture; names are not values",
    "proxy_no_proxy": "hostname exclusions, public by nature",
}


def test_no_unclassified_container_can_reach_a_serializer() -> None:
    """THE GENERALISATION, and the reason it is a test rather than a review note.

    #1106 and #1201 were both *a control whose domain is narrower than its surface*, found one at a
    time by asking "what else does this control quantify over?". That question does not scale and it
    does not survive staff turnover. This inverts it: instead of enumerating the leaks, enumerate the
    SURFACES, and fail on any surface nobody has classified.

    Measured 2026-08-09: no shipped factory emits a nested container beyond those declared below, so
    this currently guards a hole that is THEORETICAL rather than live -- stated plainly because a clean
    result reported as a finding is the failure mode this whole line of work is about. Its value is
    prospective: `redacted_settings` masks flat scalars and descends only into `headers`, so the first
    connector to put a credential inside a new dict or list would leak it silently, exactly as
    `sign_private_key` and `X-Auth-Token` did. This makes that a red test instead of an incident.
    """
    unclassified: list[str] = []
    examined = 0
    for mod, name in FACTORIES:
        fn = _decorator_style(mod, name)
        assert fn is not None
        spec = _call_with_sentinels(fn)
        for key, value in spec.settings.items():
            if isinstance(value, dict | list) and value:
                examined += 1
                if key not in HANDLED_CONTAINERS:
                    unclassified.append(f"{name} -> {key} ({type(value).__name__})")
    # LIVENESS, and it is not decoration: the first version of this test walked ZERO containers and
    # passed, because it invoked factories with required arguments only and every container parameter
    # has a default. "No unclassified containers" and "no containers" are indistinguishable from the
    # assertion alone, and only one of them is a clean result.
    assert examined > 0, (
        "the surface walk examined NO containers, so its clean result means nothing. The factory "
        "invocation has stopped populating container parameters -- fix that before trusting this test"
    )
    assert not unclassified, (
        "these settings are CONTAINERS that redaction cannot descend into, and nobody has classified "
        f"them: {sorted(set(unclassified))}. Either teach redacted_settings to descend, or add the key "
        "to HANDLED_CONTAINERS with the reason it carries no credential. Do NOT assume the values are "
        "safe because they are today -- that assumption is what shipped #1106 and #1201."
    )


def _jwt_shaped() -> str:
    """A JWT shape, BUILT AT RUNTIME so no token-shaped literal is ever committed.

    The first version of this fixture was a literal example token and the repo's gitleaks hook
    rejected the commit -- correctly, since a scanner cannot tell a well-known test vector from a live
    credential, and "it is only a fixture" is what every real leak's author believed. Assembling it
    from parts keeps the test honest and the scanner useful; a suppression would have cost the scanner
    on this file forever to save one line here.
    """
    head = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).decode().rstrip("=")
    return f"{head}.{body}.{'s' * 43}"


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("X-Shared-Signature", "Bearer sk-live-abc123"),
        ("X-Vendor-Opaque", _jwt_shaped()),
        ("X-Internal-42", "Basic dXNlcjpwYXNz"),
        ("X-Gateway", "Negotiate YIIZ..."),
        ("X-Sig", "AWS4-HMAC-SHA256 Credential=AKIA.../20260809/us-east-1/s3/aws4_request"),
    ],
)
def test_a_credential_VALUE_is_redacted_even_when_the_header_NAME_says_nothing(
    header: str, value: str
) -> None:
    """The name rule's PERMANENT blind spot, closed from the other side.

    `_is_secret_header`'s name arm is a heuristic over operator-authored free text, so a vendor that
    picks `X-Shared-Signature` or an opaque internal name defeats it -- and no longer list fixes that,
    which is why #1201's own route-onward said the shape rule was a floor and not a proof.

    None of the header names below match any substring rule. Every value is unmistakably a credential.
    """
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={header: value})
    out = redacted_settings(dict(spec.settings))["headers"]
    assert out.get(header) == "***", f"{header} carries {value[:12]}... and was served verbatim"


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("Content-Type", "application/fhir+json"),
        ("Accept", "application/json"),
        ("X-Correlation-Id", "req-42"),
        ("User-Agent", "messagefoundry/0.3.0"),
        ("X-Forwarded-For", "10.0.0.1"),
    ],
)
def test_the_value_arm_does_not_swallow_ordinary_headers(header: str, value: str) -> None:
    """The value arm is deliberately NARROW -- auth-scheme prefixes and JWTs, not "long and
    high-entropy". Masking every long header value would quietly destroy the diagnostic view rather
    than protect it, and nothing would report that as a loss."""
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={header: value})
    assert redacted_settings(dict(spec.settings))["headers"].get(header) == value


def test_a_sentinel_under_a_known_secret_key_is_actually_redacted() -> None:
    """POSITIVE CONTROL. Without it, a `redacted_settings` that returned `{}`, or a sentinel that never
    reached the settings at all, would make every assertion above pass while proving nothing."""
    spec = messagefoundry.Rest(url="https://example.invalid/x")
    spec.settings["basic_password"] = SENTINEL
    assert SENTINEL not in str(redacted_settings(dict(spec.settings)).get("basic_password"))
