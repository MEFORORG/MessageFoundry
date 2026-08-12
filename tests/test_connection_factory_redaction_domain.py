# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every connection factory's EMITTED settings survive `redacted_settings` (BACKLOG #1106).

This is the FOURTH guard against one class, and the first three ALL failed the same way: **they chose
a domain narrower than the surface.** The third was written by the author of this sentence, against
exactly that failure, and made it anyway.

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

3. This file's own first version DERIVED the domain by AST -- and then filtered it through
   ``_decorator_style``, keeping 4 of 23. Every base constructor was dropped, so
   ``Database.odbc_params`` served an ODBC password verbatim while the guard was green (BACKLOG
   #1206). Deriving the domain is not enough if something narrows it afterwards.

**The domain is DERIVED and its COVERAGE IS ASSERTED.** It is every function in the package annotated
to return a ``ConnectionSpec``, found by AST -- all 23, decorators and base constructors alike -- and
``test_the_domain_covers_every_spec_returning_function`` fails if any discovered function is missing
from it. That assertion is the lesson of defect 3: every other control here answers *is this instrument
working*; only that one answers *is it pointed at the whole thing*.
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
#:
#: ``user`` was ADDED after this vocabulary was measured against the engine's own classification
#: (BACKLOG #1106 follow-up). It is not cosmetic: this tuple decides WHERE a sentinel is injected, so a
#: word missing from it makes every assertion in this file blind to that parameter -- and the engine
#: already classifies five usernames as secret (``username``, ``basic_user``, ``proxy_user``,
#: ``ws_username``, ``credential_username``) on the stated defence-in-depth ground that a username leaks
#: directory structure. Four of those five contain no substring above, so this file had never probed a
#: username parameter at all. ``with_http_digest(user=...)`` -> ``http_auth_user`` was the sixth member
#: of that class and the one nobody had classified; it was served verbatim by ``/metadata`` and printed
#: by ``graph --json`` beside a ``proxy_user`` that masked correctly on the SAME object.
#:
#: THE DOMAIN LESSON REPEATS ONE LEVEL DOWN. Defect 3 below was a hand-chosen domain of FACTORIES;
#: this was a hand-chosen domain of WORDS, inside the file written to fix defect 3. So the vocabulary
#: is no longer only asserted by review -- see
#: ``test_the_injection_vocabulary_covers_every_key_the_engine_itself_classifies``.
CREDENTIAL_ISH = ("password", "secret", "token", "key", "credential", "passphrase", "user")

#: Keys that contain a credential-ish substring but are NOT secrets, each needing a stated reason.
#: This is the only allowlist in the file and it is about KEYS, not about values.
NOT_A_SECRET: dict[str, str] = {
    "signing_key": (
        "a PATH to the sender's PEM/DER key, not the material -- wiring.py documents it as such and "
        "transports/direct.py _read_file()s it. The engine classifies signing_key_password and NOT "
        "signing_key deliberately; that asymmetry is correct, not an oversight"
    ),
    "odbc_password_key": (
        "the NAME of the ODBC keyword to put the password under (default 'PWD'), not the password. "
        "Naming indirection, same class as sign_key_id"
    ),
    "odbc_user_key": "the NAME of the ODBC user keyword (default 'UID'), not the user",
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


def _resolve(mod: str, name: str) -> Any | None:
    """Return the callable, or None if it cannot be imported.

    NO STYLE FILTER. Its predecessor `_decorator_style` kept only `(spec, *, ...)` decorators, which
    was 4 of 23 spec-returning functions -- every base connector constructor, including `Database`,
    `Rest` and `MLLP`, was silently dropped. The `odbc_params` credential disclosure (BACKLOG #1206)
    lives in `Database`, so the guard written against exactly this class could not see it.

    The filter was convenience presented as scope: decorators take an existing spec and base
    constructors have to be built, which is more work. All 23 are constructible with naive arguments --
    measured, not assumed -- so there is no excuse left. If one ever stops being constructible, list it
    explicitly as unreachable-by-this-test rather than letting a predicate drop it silently.
    """
    fn = getattr(importlib.import_module(mod), name, None)
    return fn if callable(fn) else None


def _takes_a_spec(fn: Any) -> bool:
    params = list(inspect.signature(fn).parameters.values())
    return bool(params) and params[0].name == "spec"


def _call_with_sentinels(fn: Any) -> Any:
    """Invoke the factory with SENTINEL in every credential-shaped parameter.

    Handles BOTH shapes: a decorator gets a base spec as its first argument, a base constructor is
    built outright.
    """
    decorator = _takes_a_spec(fn)
    params = list(inspect.signature(fn).parameters.values())
    kwargs: dict[str, Any] = {}
    required: set[str] = set()
    for p in params[1:] if decorator else params:
        if p.kind not in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD):
            continue
        ann = str(p.annotation)
        if _is_credential_param(p.name):
            kwargs[p.name] = SENTINEL
        elif p.default is inspect.Parameter.empty:
            required.add(p.name)
            # A required non-credential argument. Any plausible value keeps the call alive; the
            # assertion is about credential values, not this one.
            kwargs[p.name] = (
                "https://example.invalid/token"
                if "url" in p.name.lower()
                else 2575
                if ("int" in ann and "str" not in ann)
                else "SELECT 1"
                if "statement" in p.name
                else "x"
            )
        elif _is_container_param(p):
            # OPTIONAL CONTAINER PARAMETERS ARE POPULATED DELIBERATELY. Passing only the REQUIRED
            # arguments left every container empty, and the surface walk skips empty containers -- so
            # it examined nothing and passed vacuously. A guard that passes because it looked at
            # nothing is the defect this file exists for, and it nearly shipped inside the
            # generalisation of it.
            kwargs[p.name] = (
                {"PWD": SENTINEL, "Encrypt": "yes"}
                if "odbc" in p.name
                else {"X-Probe-Auth": SENTINEL}
                if _is_mapping_param(p)
                else ["X-Probe"]
            )
    base = messagefoundry.Rest(url="https://example.invalid/endpoint")

    def build(kw: dict[str, Any]) -> Any:
        return fn(base, **kw) if decorator else fn(**kw)

    try:
        return build(kwargs)
    except Exception as exc:  # noqa: BLE001 - the refusal message IS the signal here
        if "env(" not in str(exc):
            raise
        # THE CONNECTOR REFUSES AN INLINE CREDENTIAL AND DEMANDS env(). That is the STRONGER control:
        # the value never resolves into settings at all, so no serializer can leak it. `Http` and
        # `Soap` do this for their intake credentials. `odbc_params` is the surface that does NOT
        # (BACKLOG #1206), which is precisely why it leaked and they did not.
        for k, v in list(kwargs.items()):
            if v is SENTINEL:
                kwargs[k] = messagefoundry.env(f"probe_{k}")
            elif isinstance(v, dict) and any(x is SENTINEL for x in v.values()):
                # SOAP body_secrets is {placeholder_token: env(secret_key)} BY CONTRACT -- the
                # factory forbids an inline literal there, which is the env()-only treatment
                # odbc_params lacks. Mirror the contract rather than skipping the connector.
                kwargs[k] = {
                    ik: (messagefoundry.env(f"probe_{ik}") if iv is SENTINEL else iv)
                    for ik, iv in v.items()
                }
        try:
            return build(kwargs)
        except Exception:  # noqa: BLE001
            # Still refused -- these connectors COUPLE their parameters (setting `intake_api_key`
            # without `intake_auth` is itself rejected), and encoding each connector's coupling rules
            # here would put connector-specific knowledge in a generic domain test.
            #
            # Drop the credential parameters and build the connector plainly. It stays IN the domain
            # for the container walk, and `test_a_refusing_connector_actually_refuses` asserts the
            # refusal separately. A connector excluded from the domain is a hole; a connector whose
            # credential path is covered by a refusal instead of by redaction is a documented fact.
            REFUSES_INLINE_CREDENTIALS.add(getattr(fn, "__name__", "?"))
            # REQUIRED ARGUMENTS ONLY. Dropping just the credentials was not enough: these
            # connectors also refuse an OPTIONAL control that is set while its gate is off
            # (`intake_client_subjects` with `intake_auth='none'`), on the stated grounds that a
            # control configured but never consulted reads as protection that does not exist.
            # That refusal is correct and this test has no business working around it.
            return build({k: v for k, v in kwargs.items() if k in required})


def _is_envref(v: Any) -> bool:
    return type(v).__name__ == "EnvRef"


#: Connectors that REFUSE an inline credential outright. Populated by `_call_with_sentinels` as a
#: side effect of discovering it, and asserted non-empty below -- if it empties, either every
#: connector stopped refusing (a real regression) or the detection broke.
REFUSES_INLINE_CREDENTIALS: set[str] = set()


#: THE DOMAIN: every spec-returning public function, decorators AND base constructors. 23 of them.
FACTORIES = [(mod, name) for mod, name in _factories_returning_a_spec() if _resolve(mod, name)]


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
    fn = _resolve(mod, name)
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
    "odbc_params": "per-key via _is_secret_odbc_key (BACKLOG #1206)",
    "calling_ae_allowlist": (
        "DICOM AE TITLES that may connect -- an allowlist of peer identifiers. Naming who may "
        "call is not a credential, and masking it would hide the access-control decision from "
        "the operator who has to audit it"
    ),
    "presentation_contexts": (
        "DICOM SOP class / transfer syntax negotiation -- protocol capability, public by nature"
    ),
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

    THE MEASUREMENT CLAIM THAT USED TO SIT HERE IS DELETED, NOT SOFTENED. It read "Measured
    2026-08-09: no shipped factory emits a nested container beyond those declared below, so this
    currently guards a hole that is THEORETICAL rather than live". Both halves were FALSE. The walk
    ran over 4 of 23 spec-returning functions -- every base constructor was dropped by a style filter
    -- and `Database.odbc_params` was carrying a live credential disclosure the whole time (BACKLOG
    #1206). A number a test has not established has no business in the file that defines the test, and
    a softened version ("largely", "in the main") would be worse: it keeps the authority and loses the
    falsifiability. The domain size is now ASSERTED below instead of described here.
    """
    unclassified: list[str] = []
    examined = 0
    for mod, name in FACTORIES:
        fn = _resolve(mod, name)
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


def test_the_domain_covers_every_spec_returning_function() -> None:
    """THE ASSERTION THAT WOULD HAVE CAUGHT #1206, and the one this file most needed.

    Its predecessor filtered the domain through `_decorator_style` and kept 4 of 23. Every base
    connector constructor -- `Database`, `Rest`, `MLLP` -- was dropped, and `Database.odbc_params` was
    serving an ODBC password verbatim the entire time the guard was green.

    Every control in this file answers *is this instrument working*: make it fail on purpose, confirm
    the injection landed, run a negative control, assert it examined something. NONE of them answers
    *is it pointed at the whole thing*. The domain is a separate claim and needs its own evidence, so
    here it is.
    """
    discovered = {n for _, n in _factories_returning_a_spec()}
    covered = {n for _, n in FACTORIES}
    assert discovered - covered == set(), (
        f"these spec-returning functions are NOT in the tested domain: {sorted(discovered - covered)}. "
        "A connector missing from the domain is invisible to every other assertion in this file."
    )
    assert len(covered) >= 23, (
        f"domain shrank to {len(covered)}; it was 23 when #1206 was fixed. A shrinking domain is how "
        "this defect class recurs -- it has done so four times."
    )


def test_the_injection_vocabulary_covers_every_key_the_engine_itself_classifies() -> None:
    """THE FIFTH INSTANCE OF THE CLASS, one level below where the previous four lived.

    Defects 1-3 above were domains of THINGS -- a frozenset of keys, a set of parameter names, a
    filtered set of factories. This is a domain of WORDS: :data:`CREDENTIAL_ISH` decides which
    parameters get a sentinel, so a word missing from it makes every other assertion in this file
    silently blind to that parameter. It was hand-written, and it omitted ``user``.

    Measured at engine ``48f8712d``, before the fix: widening this tuple by the single word ``user``
    and changing nothing else turned the parametrised assertion above red on exactly
    ``with_http_digest -> http_auth_user`` and on nothing else. One factory, one setting -- a specific
    red, which is the kind worth having.

    DERIVED, NOT LISTED. The engine's own ``_SECRET_SETTING_KEYS`` is the statement of what it believes
    is a credential. If it classifies a key this file's vocabulary cannot see, then a parameter feeding
    that key can never be probed here, and the guard is narrower than the thing it guards. That is
    checkable against the running code rather than by review, so it is checked.
    """
    from messagefoundry.config.wiring import _SECRET_SETTING_KEYS

    blind = sorted(k for k in _SECRET_SETTING_KEYS if not _is_credential_param(k))
    assert not blind, (
        "the engine classifies these settings as credentials, but this file's injection vocabulary "
        f"(CREDENTIAL_ISH / NOT_CREDENTIAL_SUFFIX) does not recognise their shape: {blind}. A "
        "parameter that feeds one of them is never given a sentinel, so every assertion in this file "
        "is blind to it -- which is exactly how http_auth_user leaked past a guard written for this "
        "class. Widen CREDENTIAL_ISH; do not narrow the engine."
    )


def test_the_digest_username_is_masked_like_every_other_username() -> None:
    """BACKLOG #1106 follow-up, measured at ``48f8712d`` before the fix.

    ``with_http_digest`` crosses the same parameter-to-setting boundary ``with_signing`` crosses:
    parameter ``user`` becomes setting ``http_auth_user``, parameter ``password`` becomes
    ``http_auth_password``. Only the password half was classified::

        http_auth_user      -> 'SYNTHETIC-...-DIGEST'    <-- verbatim, both serializers
        http_auth_password  -> '***'
        proxy_user          -> '***'                      <-- the SAME object, the SAME class
        proxy_password      -> '***'

    and the ``env()`` FALLBACK DEFAULT rode along with it, while the identical ``env()`` on
    ``proxy_user`` correctly emitted a bare ``{'env': key}``.

    This is pinned by NAME as well as by the derived probe above, because the two fail for different
    reasons: the derived probe dies if the vocabulary regresses, this one dies if the classification
    does. A username is masked here defence-in-depth on the engine's own stated ground -- it names a
    principal and can leak directory structure, which is why the other five are masked.
    """
    from messagefoundry.transports.http_auth import with_http_digest

    inline = with_http_digest(
        messagefoundry.Rest(
            url="https://example.invalid/x",
            proxy="http://proxy.invalid:8080",
            proxy_user=SENTINEL,
            proxy_password="pw",
        ),
        user=SENTINEL,
        password="pw2",
    )
    out = redacted_settings(dict(inline.settings))
    assert out["http_auth_user"] == "***", out["http_auth_user"]
    assert out["proxy_user"] == "***"  # the control: its sibling was already right
    assert out["http_auth"] == "digest"  # and the MODE stays readable -- it is not a credential

    fallback = with_http_digest(
        messagefoundry.Rest(url="https://example.invalid/x"),
        user=messagefoundry.env("probe_digest_user", default=SENTINEL),
        password=messagefoundry.env("probe_digest_password", default="pw"),
    )
    got = redacted_settings(dict(fallback.settings))["http_auth_user"]
    assert got == {"env": "probe_digest_user"}, got
    assert SENTINEL not in str(got)


def test_a_refusing_connector_actually_refuses_an_inline_credential() -> None:
    """The connectors that demand `env()` have a STRONGER control than redaction, and it is asserted.

    `Http` and `Soap` refuse an inline intake credential outright, so the value never resolves into
    settings and no serializer can leak it. That is the treatment `odbc_params` lacks -- there, `env()`
    is refused and the inline literal is the only expressible form, which is the whole of #1206.

    `_call_with_sentinels` discovers these by trying an inline credential and reading the refusal. If
    this set empties, either every connector stopped refusing (a real regression) or the discovery
    broke -- and both must go red rather than pass quietly.
    """
    for mod, name in FACTORIES:
        _call_with_sentinels(_resolve(mod, name))
    assert REFUSES_INLINE_CREDENTIALS, (
        "no connector refused an inline credential. Either the env()-only refusals were removed, or "
        "_call_with_sentinels stopped detecting them; a green here proves neither."
    )


# --- BACKLOG #1207: two holes INSIDE containers the control claims to handle -----------------------


def test_an_env_ref_inside_a_headers_table_does_not_disclose_its_default() -> None:
    """A hole inside the ONE container the header rule already covered.

    The headers branch had no `EnvRef` arm, so an `env()` ref in a headers table came back as the RAW
    object -- not JSON-safe, and carrying its `default` intact -- while the same `env()` on a top-level
    credential correctly emits `{"env": key}` with the default dropped.

    The measured instance used `X-Vendor-Thing`, which matches no credential substring. That is why the
    default is now dropped for EVERY header rather than only credential-shaped ones: a header value
    sourced from `env()` is a credential by intent, and the name heuristic is precisely the gate that
    failed here.
    """
    spec = messagefoundry.Rest(
        url="https://example.invalid/x",
        headers={"X-Vendor-Thing": messagefoundry.env("acme_key", default=SENTINEL)},
    )
    got = redacted_settings(dict(spec.settings))["headers"]["X-Vendor-Thing"]
    assert got == {"env": "acme_key"}, got
    assert SENTINEL not in str(got)


def test_a_credential_in_url_userinfo_is_masked_on_url_and_proxy_url() -> None:
    """`url="https://user:SECRET@host"` was returned verbatim while `proxy_password` on the SAME
    object masked -- safe in the typed field, disclosed in the URL beside it."""
    spec = messagefoundry.Rest(
        url=f"https://user:{SENTINEL}@example.invalid/y",
        proxy=f"http://puser:{SENTINEL}@proxy.invalid:8080",
        proxy_password="pp",
    )
    out = redacted_settings(dict(spec.settings))
    assert SENTINEL not in str(out.get("url")), out.get("url")
    assert SENTINEL not in str(out.get("proxy_url")), out.get("proxy_url")
    # The user, host and path SURVIVE. Masking the whole URL would destroy the operator's view rather
    # than protect it, and nothing would report that as a loss.
    assert "user:***@example.invalid/y" in str(out["url"])


def test_a_url_without_userinfo_is_left_alone() -> None:
    """The control half. A masker that rewrites every URL would pass the assertions above while
    silently mangling ordinary configuration."""
    spec = messagefoundry.Rest(url="https://plain.invalid/path?q=1&r=2")
    assert redacted_settings(dict(spec.settings))["url"] == "https://plain.invalid/path?q=1&r=2"
