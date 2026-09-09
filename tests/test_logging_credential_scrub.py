# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The WRITE-TIME log handler filters carry a credential vocabulary (BACKLOG #1478).

The three filters ``logging_setup._install_phi_filters`` installed carried none. Measured 2026-09-06 by
driving all three in sequence over a ``LogRecord``: ``encryption_key=``, ``vault_token=``,
``client_secret=``, ``ad_bind_password=``, ``tls_key_password=``, ``private_key=`` and
``Authorization: Bearer <tok>`` passed VERBATIM, with the OIDC ``code=``/``state=`` control scrubbing in
the same run. Those filters are the only thing between a log call and the two sinks that leave the
process -- the stdout stream NSSM captures and the off-box syslog forwarder -- so
``support/redact.py``, a second pass over the support archive and ``GET /logs/tail``, cannot reach a
record already sent.

WHAT THIS FILE ASSERTS, and why each part is here rather than folded into the next:

1. **The chain scrubs.** Every family runs through the PRODUCTION filter chain in production order,
   not through :func:`~messagefoundry.secretscrub.scrub_credentials` alone -- a pass against the bare
   function would prove nothing about whether the filter is installed or whether an upstream filter
   mangles the line first.
2. **The family's own pattern is what did it.** ``test_each_family_survives_when_its_own_pattern_is
   _disabled`` disables the declared pattern and REQUIRES the secret to leak. This is the assertion
   that tells "the pattern works" apart from "something else happened to cover it", which is the exact
   false green BACKLOG #1183 shipped on the sibling surface for months.
3. **The admission gates cannot narrow.** ``scrub_credentials`` skips a pattern whose keyword scan
   finds nothing. That is safe only because both are built from one word tuple, so the suite compares
   the gated and ungated passes over every fixture rather than trusting the argument.
4. **The domain is the engine's own.** ``test_every_engine_credential_setting_is_scrubbed_or_excluded``
   reads ``config/wiring.py::_SECRET_SETTING_KEYS`` and ``config/settings.py::_FILE_SECRET_KEYS`` and
   requires every name to be scrubbed by the chain or excused in :data:`EXCLUDED_FROM_SCRUBBING` with
   a reason -- the derived-domain shape BACKLOG #1475 built for the read-time surface, pointed at the
   write-time one. A credential setting added to the engine that the log filters cannot see reds this
   file rather than shipping as a silent hole.

Every sentinel is invented HERE, never derived from the code under test, and every one carries a
hyphen AND an underscore so no fixture can go green on a base64-shaped accident. They are synthetic
and carry no real credential, host or site.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import pytest

from messagefoundry import secretscrub
from messagefoundry.logging_setup import (
    ControlCharScrubFilter,
    CredentialQueryScrubFilter,
    CredentialScrubFilter,
    RedactionFilter,
    _install_phi_filters,
)
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER

#: A pattern that can never match, used to disable one module pattern for the mutation fixture.
NEVER_MATCHES = re.compile(r"(?!x)x")


def run_chain(
    message: str,
    *,
    args: tuple[object, ...] | None = None,
    exc_text: str | None = None,
) -> logging.LogRecord:
    """Drive one record through the PRODUCTION filter chain, in production order.

    Built by :func:`_install_phi_filters` itself rather than by listing the filters here, so this
    helper cannot drift from what a real handler carries -- and so a fixture cannot pass against a
    chain that no handler has. ``args`` builds a LAZY record, which is what almost every real
    logging call in this engine is."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    record = logging.LogRecord("t", logging.INFO, __file__, 1, message, args, None)
    record.exc_text = exc_text
    for handler_filter in handler.filters:
        assert isinstance(handler_filter, logging.Filter)
        handler_filter.filter(record)
    return record


@dataclass(frozen=True)
class Family:
    """One credential family: a log line, the value that must not survive it, and the module patterns
    that are supposed to be doing the work."""

    name: str
    line: str
    secret: str
    patterns: tuple[str, ...]


#: Every credential family the write-time chain must scrub. The first seven are the shapes measured
#: passing VERBATIM at 68693cfc2, in the order they were measured.
FAMILIES: tuple[Family, ...] = (
    Family(
        name="store_encryption_key",
        line="opening store encryption_key=wt-Enc_Key-51 active",
        secret="wt-Enc_Key-51",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        name="vault_token",
        line="connecting vault_token=wt-V4ult_Tok-52 to kv store",
        secret="wt-V4ult_Tok-52",
        patterns=("_BEARER",),
    ),
    Family(
        name="oidc_client_secret",
        line="oidc discovery failed client_secret=wt-Cli_Sec-53 rejected",
        secret="wt-Cli_Sec-53",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="ad_bind_password",
        line="ldap bind failed ad_bind_password=wt-Ad_Bind-54 for svc",
        secret="wt-Ad_Bind-54",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="tls_key_password",
        line="api tls tls_key_password=wt-Tls_Key-55 could not open the chain",
        secret="wt-Tls_Key-55",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="private_key_material",
        line="signing setup private_key=wt-Priv_Key-56 for IB_ACME_ADT",
        secret="wt-Priv_Key-56",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        # TWO patterns cover this one and BOTH are declared. ``_BEARER`` reaches the labelled
        # "Authorization:" header shape; ``_AUTH_SCHEME`` reaches the bare scheme. Declaring only one
        # reds the mutation fixture below, which is that fixture doing its job.
        name="authorization_bearer_header",
        line="upstream sent Authorization: Bearer wt-Bearer_Hdr-57",
        secret="wt-Bearer_Hdr-57",
        patterns=("_BEARER", "_AUTH_SCHEME"),
    ),
    # --- the rest of the write-path vocabulary -----------------------------------------------------
    Family(
        name="bare_auth_scheme",
        line="retrying with Bearer wt-Bearer_Bare-58",
        secret="wt-Bearer_Bare-58",
        patterns=("_AUTH_SCHEME",),
    ),
    Family(
        # The exact shape ``resolve_env_settings`` emits on a cast failure -- an engine error string,
        # not a hypothetical.
        name="quoted_env_value_echo",
        line="setting 'password' (env 'MEFOR_VALUE_PW'='wt-C4st_Val-59'): bad",
        secret="wt-C4st_Val-59",
        patterns=("_MEFOR_SECRET",),
    ),
    Family(
        name="odbc_pwd",
        line="odbc conn Driver={ODBC Driver 18};UID=svc;PWD=wt-0dbc_Pass-60;",
        secret="wt-0dbc_Pass-60",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="dsn_inline_password",
        line="store dsn postgres://svc:wt-D5n_Pass-61@db.invalid:5432/mefor",
        secret="wt-D5n_Pass-61",
        patterns=("_DSN_PASSWORD",),
    ),
    Family(
        # A COMMA-JOINED list (``store/keyprovider.py::_split_retired``). The sentinel is the LAST
        # element, which a comma-terminated value class would have printed verbatim -- and unlike the
        # support-bundle surface there is no long-base64 sweep behind this one to catch it.
        name="retired_encryption_keys_list",
        line="rotation ready encryption_keys_retired=wt-Ret_A-62,wt-Ret_B-63,wt-Ret_C-64 done",
        secret="wt-Ret_C-64",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        name="intake_api_key_rotation_partner",
        line="listener armed intake_api_key_next=wt-N3xt_Key-65 pending",
        secret="wt-N3xt_Key-65",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        # The label prefix carries this one: the module has no ``smart_private_key`` alternate.
        name="prefixed_private_key_material",
        line="smart backend smart_private_key=wt-Sm4rt_Key-66 configured",
        secret="wt-Sm4rt_Key-66",
        patterns=("_KEY_MATERIAL",),
    ),
)


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_the_production_filter_chain_scrubs_every_credential_family(fam: Family) -> None:
    """The value must not survive the chain, and the reader must see that redaction happened."""
    out = run_chain(fam.line).getMessage()
    assert fam.secret not in out, f"{fam.name}: the credential survived the chain -- got {out!r}"
    assert CREDENTIAL_PLACEHOLDER in out, f"{fam.name}: nothing was marked redacted -- got {out!r}"


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_each_family_survives_when_its_own_pattern_is_disabled(
    fam: Family, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the family's declared patterns disabled, the credential MUST leak.

    A pass here means the declared patterns are the ones doing the work. A failure means something
    else in the chain -- the PHI pass, the query-parameter filter, another credential pattern -- is
    covering this family, so its green is not evidence about its own pattern. That is exactly how the
    sibling surface's bearer defect stayed green for months (BACKLOG #1183).

    Patching the module attribute is enough because ``secretscrub._run`` is straight-line code
    reading its globals at call time. An earlier draft held the patterns in a table, which captured
    them by value: the patch then mutated nothing and every family 'leaked' for the wrong reason --
    a green that means the opposite of what it says."""
    for name in fam.patterns:
        assert isinstance(getattr(secretscrub, name), re.Pattern), (
            f"{fam.name} declares {name!r}, which is not a pattern on the module"
        )
        monkeypatch.setattr(secretscrub, name, NEVER_MATCHES)
    out = run_chain(fam.line).getMessage()
    assert fam.secret in out, (
        f"{fam.name}: disabling {list(fam.patterns)} did NOT make the credential leak -- something "
        f"else is covering it, so this family proves nothing about its pattern. Got {out!r}"
    )


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_the_hint_gates_never_change_the_result(fam: Family) -> None:
    """The gated pass and the ungated pass must agree, byte for byte.

    ``scrub_credentials`` skips a pattern whose keyword scan finds nothing, which is safe only because
    the gate and the pattern are built from one word tuple. That is an argument; this is the check.
    A gate that has drifted narrower than its pattern shows up here as a disagreement, and nowhere
    else -- the family assertions above would still pass, because a narrowed gate that happens to
    admit the fixture is indistinguishable from a correct one."""
    for line in (fam.line, fam.secret, fam.line.upper(), fam.line.lower()):
        assert secretscrub.scrub_credentials(line) == secretscrub._run(
            line, CREDENTIAL_PLACEHOLDER, None
        ), f"{fam.name}: the admission gate changed the result on {line!r}"


def test_the_gate_folds_the_way_the_patterns_match_not_the_way_str_lower_does() -> None:
    """``casefold()``, not ``lower()`` -- and the difference is a real leak, not a style note.

    The patterns are ``(?i)`` and Python's case-insensitive matching folds beyond ASCII: measured on
    this interpreter, ``re.match("(?i)s", "\u017f")`` and ``re.match("(?i)k", "\u212a")`` both match.
    ``"\u017f".lower()`` is unchanged, so a ``lower()``-folded gate does NOT admit a line the pattern
    behind it WOULD have matched -- the one direction a gate must never fail in. Measured: with
    ``lower()`` the admission test returns False on the line below and the credential survives; with
    ``casefold()`` it is admitted and scrubbed.

    The character is built from its code point so no encoding layer between here and disk can eat it.
    """
    long_s = chr(0x17F)  # LATIN SMALL LETTER LONG S
    line = f"connect failed pa{long_s}sword=wt-F0ld_Chk-72 for svc"

    # The pattern itself reaches it, so there IS something for the gate to be wrong about.
    assert "wt-F0ld_Chk-72" not in secretscrub._run(line, CREDENTIAL_PLACEHOLDER, None)
    # A lower()-folded gate would not admit the line -- this is the control that makes the next
    # assertion mean something rather than passing for any folding at all.
    assert not any(word in line.lower() for word in secretscrub._ANY_HINT)
    # And the shipped gate does admit it, so the chain scrubs it.
    assert "wt-F0ld_Chk-72" not in run_chain(line).getMessage()


#: Diagnostics carrying no credential, which the credential patterns must NOT eat. Over-redaction is
#: the safe direction for a file that leaves the box; it is NOT the safe direction here, where the
#: reader is an operator watching a live console for the message that says what to fix.
ORDINARY_DIAGNOSTICS = (
    "INFO engine started on port 8765",
    "connection IB_DEMO_ADT bound, password rotation scheduled",
    # THE TWO THAT DISCRIMINATE ON THE AUTH-SCHEME WORD SET. Both are eaten by a widened
    # ``(bearer|basic|digest)`` alternate and survive the shipped "bearer"-only one. The engine's
    # real strings -- "oauth2_auth_style must be 'basic' or 'post'" and "ws_password_type must be
    # 'text'" -- QUOTE the word, so the pattern's whitespace run cannot match and they survive a
    # wide pattern and a narrow one alike. Using those as the guard would look like coverage and
    # test nothing (measured under BACKLOG #1475 on the sibling surface).
    "server offered digest challenge, retrying",
    "falling back to basic auth for this hop",
    # The label prefix reaches a credential word at the TAIL of a snake_case label. These carry the
    # word in the MIDDLE, where the trailing "\b" cannot fire, so a path and a mode name survive.
    "password_file=/etc/mefor/pw.txt",
    "ws_password_type=text on the SOAP hop",
    # A header NAME, a PATH and a REFERENCE the key-material alternates must leave alone.
    "intake_api_key_header=x-acme-key on the listener",
    "private_key_file=/etc/mefor/sign.pem loaded",
    "encryption_key_ref=vault-kv-store-dek resolved",
    # THE ONE THAT IS SPECIFIC TO THIS SURFACE. The support-bundle redactor sweeps any base64-shaped
    # run over 24 characters; this module deliberately does not, because an idempotency key is how an
    # operator traces a message through the staged pipeline and it is the single most common "_key"
    # identifier in this tree.
    "idempotency_key=IB-ACME-ADT-0000000012345678 delivered",
)


@pytest.mark.parametrize("line", ORDINARY_DIAGNOSTICS)
def test_ordinary_engine_diagnostics_survive_the_chain_intact(line: str) -> None:
    """A diagnostic that carries no credential must reach the operator unchanged."""
    assert run_chain(line).getMessage() == line


def test_a_credential_inside_an_exception_traceback_is_scrubbed() -> None:
    """``Formatter.format`` appends ``exc_text`` VERBATIM, so a credential in a traceback reaches the
    sink whatever happens to the rendered message.

    The realistic vector: a store or connector raises with its DSN in the message, and an outer-loop
    ``log.exception(...)`` renders the whole traceback into the general log. ``RedactionFilter`` runs
    first and is what populates ``exc_text``, which is why the credential filter is installed after
    it rather than before."""
    record = run_chain(
        "delivery failed",
        exc_text="Traceback:\n  OperationalError: postgres://svc:wt-Tr4ce_Back-67@db.invalid/mefor",
    )
    assert record.exc_text is not None
    assert "wt-Tr4ce_Back-67" not in record.exc_text
    assert CREDENTIAL_PLACEHOLDER in record.exc_text


def test_the_credential_filter_is_installed_after_redaction_and_before_control_chars() -> None:
    """Order is load-bearing in BOTH directions, so it is pinned rather than described.

    After ``RedactionFilter``: that filter is what renders ``exc_info`` into ``exc_text`` and clears
    it, so a credential filter running first would find no traceback to scrub. Before
    ``ControlCharScrubFilter``: that one must stay last, because it is what guarantees no field can
    begin a new physical line."""
    handler = logging.NullHandler()
    _install_phi_filters(handler)
    order = [type(f) for f in handler.filters]
    assert order.index(RedactionFilter) < order.index(CredentialScrubFilter)
    assert order.index(CredentialScrubFilter) < order.index(ControlCharScrubFilter)
    # And the query-parameter filter is still there: this change adds a vocabulary, it does not
    # replace the OIDC one (the two are kept apart on the grounds in secretscrub's docstring).
    assert CredentialQueryScrubFilter in order


def test_the_chain_is_idempotent_over_a_credential_line() -> None:
    """A record dispatched to stdout AND the off-box forwarder is filtered once per handler, so the
    two sinks must not disagree. Re-running the chain over its own output must be a no-op."""
    once = run_chain(FAMILIES[0].line).getMessage()
    twice = run_chain(once).getMessage()
    assert once == twice


def test_a_lazy_record_is_rendered_before_it_is_scrubbed() -> None:
    """A credential arriving through ``%s`` args, not baked into ``msg``, must still be scrubbed.

    Almost every real logging call in this engine is lazy, so a filter reading ``record.msg`` instead
    of ``record.getMessage()`` would scrub nothing in production while passing every fixture above."""
    record = run_chain(
        "ldap bind failed %s for %s", args=("ad_bind_password=wt-L4zy_Arg-68", "svc")
    )
    assert "wt-L4zy_Arg-68" not in record.getMessage()


def test_an_oidc_code_inside_a_traceback_is_scrubbed() -> None:
    """`CredentialQueryScrubFilter` reached only the rendered message until BACKLOG #1478.

    An exception raised while handling the OIDC callback carries the request URL, and
    ``Formatter.format`` appends the rendered traceback verbatim -- so a live authorization ``code``
    reached stdout and the off-box forwarder. ADR 0142 AC-10 says the engine SHALL NOT log it. What
    closed it was sharing ONE record walk between the scrubbing filters rather than hand-copying it
    per filter, which is how the field came to be missing from exactly one of them."""
    record = run_chain(
        "callback failed",
        exc_text="Traceback:\n  ValueError: /ui/oidc/callback?code=wt-C0de_Val-69&state=wt-St4te-70",
    )
    assert record.exc_text is not None
    assert "wt-C0de_Val-69" not in record.exc_text
    assert "wt-St4te-70" not in record.exc_text


# --- the derived domain: the vocabulary is the ENGINE'S, not this file's ---------------------------

#: A sentinel carrying a hyphen AND an underscore, so nothing base64-shaped can reach it.
_REGISTRY_SENTINEL = "wt-Sekr3t_Val-71"

#: Settings the ENGINE'S OWN classifier calls credentials that the write-time chain deliberately does
#: NOT scrub, each with the reason it is out.
#:
#: ALL SIX ARE THE USERNAME CLASS, and the class is out on grounds the engine already recorded at the
#: layer that owns it, not on taste here. ``messagefoundry/redaction.py`` states its own residual
#: outright -- the residual is an adversarially-crafted SINGLE-TOKEN identifier -- and a username is a
#: single-token identifier. ``docs/PHI.md`` says the same from the other end: the forwarded log stream
#: still carries usernames, and that is its stated reason for gating the off-box hop. Scrubbing
#: usernames here would contradict a documented position two layers deep, and it would reach the wrong
#: shape anyway: a username leaks as ``Login failed for user 'svc'``, as ``UID=svc;``, as ``CN=svc,OU=``
#: or as the engine's own ``actor=`` audit field, none of which a ``label=value`` credential rule sees.
#:
#: THE CONSEQUENCE IS WRITTEN DOWN RATHER THAN LEFT IMPLIED: the stdout log and the forwarded stream
#: can carry an operator username. ``docs/PHI.md`` already says so.
EXCLUDED_FROM_SCRUBBING: dict[str, str] = {
    "username": "username class: the generic principal setting",
    "basic_user": "username class: HTTP Basic principal",
    "credential_username": "username class: Windows/UNC share principal (ADR 0132)",
    "http_auth_user": "username class: HTTP Digest/NTLM principal",
    "proxy_user": "username class: forward-proxy principal (ADR 0126)",
    "ws_username": "username class: WS-Security UsernameToken principal (ADR 0015)",
}


def _engine_credential_settings() -> set[str]:
    """Every setting name the ENGINE classifies as a credential, read from the engine.

    Two registries, because the engine keeps two and they do not agree:
    ``config/wiring.py::_SECRET_SETTING_KEYS`` is the connector-settings set ``/metadata`` redacts, and
    ``config/settings.py::_FILE_SECRET_KEYS`` is the service-settings set that must live in the
    environment rather than the config file. Reading either alone is a domain narrower than the
    engine's own belief."""
    from messagefoundry.config.settings import _FILE_SECRET_KEYS
    from messagefoundry.config.wiring import _SECRET_SETTING_KEYS

    return set(_SECRET_SETTING_KEYS) | {key for _section, key in _FILE_SECRET_KEYS}


def test_every_engine_credential_setting_is_scrubbed_or_excluded() -> None:
    """THE VOCABULARY IS DERIVED FROM THE ENGINE, NOT HAND-CHOSEN HERE.

    This is BACKLOG #1475's derived-domain guard pointed at the WRITE-time surface. The failure it
    catches is silent in the one direction that matters: a credential setting the log filters cannot
    see does not error, it just prints -- to stdout, and to whatever collector ``forward_host`` names.

    THE ASSERTION IS TWO-SIDED ON PURPOSE. A one-sided "everything that leaks is excused" version goes
    green forever once the table is wide enough, and an exclusion that has quietly become false is a
    worse record than none: it tells a reader the engine leaks something it now scrubs."""
    names = _engine_credential_settings()

    # Positive control on the derivation. A registry import silently returning an empty or tiny set
    # would make every assertion below vacuously true.
    assert len(names) >= 25, (
        f"the engine's credential registry read as {sorted(names)} -- too small"
    )

    leaked = {
        name
        for name in names
        if _REGISTRY_SENTINEL
        in run_chain(f"connect failed {name}={_REGISTRY_SENTINEL} for endpoint").getMessage()
    }

    unexplained = leaked - set(EXCLUDED_FROM_SCRUBBING)
    assert not unexplained, (
        "the engine classifies these settings as credentials, but the write-time log filters print "
        f"their values verbatim and no reason is recorded for it: {sorted(unexplained)}. Those "
        "filters are on the stdout handler AND the off-box forwarder, so a hole lands on both. "
        "Either widen messagefoundry/secretscrub.py or add the name to EXCLUDED_FROM_SCRUBBING with "
        "the reason it is deliberately out."
    )

    stale = set(EXCLUDED_FROM_SCRUBBING) - leaked
    assert not stale, (
        f"EXCLUDED_FROM_SCRUBBING excuses these, but the chain already scrubs them: {sorted(stale)}. "
        "A stale exclusion is a false record -- it tells a reader the engine leaks something it does "
        "not. Remove the entry."
    )

    unknown = set(EXCLUDED_FROM_SCRUBBING) - names
    assert not unknown, (
        f"EXCLUDED_FROM_SCRUBBING names settings the engine's registries do not carry: "
        f"{sorted(unknown)}. The table must excuse real names, or it excuses nothing."
    )


def test_the_excluded_settings_are_the_username_class() -> None:
    """The exclusion is a CLASS THE ENGINE ALREADY NAMES, not a list of whatever happened to leak.

    Pinned separately from the derived test because the two fail for different reasons: that one dies
    if the domain regresses, this one dies if the exclusion drifts off the class the reasoning covers.
    A password, token or key landing in that table is a hole being annotated rather than fixed, and it
    would pass the derived test above."""
    for name, reason in EXCLUDED_FROM_SCRUBBING.items():
        assert reason.startswith("username class:"), (
            f"{name!r} is excused with {reason!r}. Only the username class is excusable here -- "
            "anything else in this table is an unfixed hole wearing a reason."
        )
        assert "user" in name or "username" in name, (
            f"{name!r} is excused as a username but does not look like one. If the engine has "
            "renamed it, fix the entry; if it is a real credential, fix the module."
        )
