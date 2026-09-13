# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every secret family the shared log redactor applies a pattern for is covered by a fixture that
its own pattern must earn (BACKLOG #1183).

`messagefoundry.support.redact` is the ONLY secret backstop for two surfaces: the app-log tail inside
the support archive (`support/bundle.py`) and `GET /logs/tail` (`api/app.py`, whose docstring says it
is the same redactor). It is a small hand-written regex pass, and before this guard existed it had no
derived domain and no coverage assertion -- the narrow-domain shape that
`test_connection_factory_redaction_domain.py` documents failing four times over on the connection
settings surface.

Two failures this file is built to make impossible, both measured at 4633a295:

1. **A green that a DIFFERENT pattern bought.** The bearer assertion in `tests/test_support_bundle.py`
   passed while `_BEARER` redacted nothing at all: the pattern consumed the word ``Bearer`` as its own
   value match and emitted the token, and the line went green only because that test's chosen token was
   32 pure-alphanumeric characters and the unrelated long-base64 sweep mopped it up. A realistic token
   carrying a hyphen or an underscore broke the run, missed the sweep, and survived verbatim. So every
   fixture here uses a token with a hyphen and an underscore, and
   ``test_each_family_survives_when_its_own_patterns_are_disabled`` disables the family's declared
   patterns and REQUIRES the secret to leak -- which is the only assertion that can tell "this pattern
   works" apart from "something else happened to cover it".

2. **A domain narrower than the surface.** ``test_the_family_table_covers_every_applied_pattern``
   derives the applied set by AST from the body of ``redact_log_line`` itself, and fails if any applied
   pattern is neither claimed by a family nor named in ``NOT_A_SECRET_PATTERN``. Adding a pattern to the
   module without a fixture reds this file; so does applying one and never declaring what it is for.

The sentinel values are invented HERE, never derived from the code under test. They are synthetic and
carry no real credential, host or site.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
from dataclasses import dataclass, field

import pytest

from messagefoundry.support import redact as redact_mod
from messagefoundry.support.redact import REDACTION_PLACEHOLDER, redact_log_line

#: A pattern that can never match, used to disable one redactor pattern for the mutation fixture.
NEVER_MATCHES = re.compile(r"(?!x)x")

#: Module-level patterns that are deliberately NOT secret markers. Each needs a reason, and the exact
#: set is asserted below so adding a member is a deliberate edit rather than a silent widening.
NOT_A_SECRET_PATTERN = {
    # Protects the leading log timestamp from the shared PHI date pass. It matches a timestamp, never
    # a secret, so no secret family can or should claim it.
    "_LEADING_TS",
}


@dataclass(frozen=True)
class Family:
    """One secret family: a log line, the value that must not survive it, and the module patterns
    that are supposed to be doing the work."""

    name: str
    line: str
    secret: str
    patterns: tuple[str, ...] = field(default=())


#: Every secret family the redactor applies a pattern for. Tokens carry a hyphen AND an underscore on
#: purpose: that breaks the long-base64 run so no family can be redacted by the backstop by accident.
FAMILIES: tuple[Family, ...] = (
    # --- families that already worked at 4633a295, kept as live positive controls ------------------
    Family(
        # TWO patterns cover this one, and the second arrived later: ``_KEY_MATERIAL`` (BACKLOG #1475)
        # is case-insensitive, so ``_LABEL_PREFIX`` matches "MEFOR_STORE_" and its ``encryption_key``
        # alternate matches the SCREAMING_SNAKE tail. Declaring only ``_MEFOR_SECRET`` reds the
        # mutation fixture below, which is that fixture doing its job: an undeclared second cover is
        # exactly how a family's green stops being evidence about its own pattern.
        name="mefor_env_value",
        line="startup MEFOR_STORE_ENCRYPTION_KEY=kv-Str0ng_Key-11 loaded",
        secret="kv-Str0ng_Key-11",
        patterns=("_MEFOR_SECRET", "_KEY_MATERIAL"),
    ),
    Family(
        name="labelled_token",
        line="cache hit token: mf-sess_9aZ-Qx_7Lp",
        secret="mf-sess_9aZ-Qx_7Lp",
        patterns=("_BEARER",),
    ),
    Family(
        name="api_key_kv",
        line="calling partner api_key=ak-live_7Qp-3Zx",
        secret="ak-live_7Qp-3Zx",
        patterns=("_BEARER",),
    ),
    Family(
        name="mfb64_body",
        line="outbound blob mfb64:v1:SGVsbG9Xb3JsZEhlbGxvV29ybGQ=",
        secret="SGVsbG9Xb3JsZEhlbGxvV29ybGQ=",
        patterns=("_MFB64", "_LONG_B64"),
    ),
    Family(
        name="long_base64_run",
        line="loaded key AAAABBBBCCCCDDDDEEEEFFFFGGGG",
        secret="AAAABBBBCCCCDDDDEEEEFFFFGGGG",
        patterns=("_LONG_B64",),
    ),
    # --- families that survived VERBATIM at 4633a295 ----------------------------------------------
    Family(
        name="authorization_bearer_header",
        line="upstream sent Authorization: Bearer sk-live-AbCdEf_1234-XYZ",
        secret="sk-live-AbCdEf_1234-XYZ",
        patterns=("_BEARER", "_AUTH_SCHEME"),
    ),
    Family(
        name="bare_auth_scheme",
        line="retrying with Bearer sk-live-Zz9_Aa8-QQwe",
        secret="sk-live-Zz9_Aa8-QQwe",
        patterns=("_AUTH_SCHEME",),
    ),
    Family(
        name="password_kv",
        line="connect failed password=pw-Str0ng_Pass-22",
        secret="pw-Str0ng_Pass-22",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="odbc_pwd",
        line="odbc conn Driver={ODBC Driver 18};UID=svc;PWD=pw-0dbc_Pass-33;",
        secret="pw-0dbc_Pass-33",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="secret_kv",
        line="provider bind secret=sc-V4ult_Val-44",
        secret="sc-V4ult_Val-44",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="dsn_inline_password",
        line="store dsn postgres://svc:pw-D5n_Pass-55@db.invalid:5432/mefor",
        secret="pw-D5n_Pass-55",
        patterns=("_DSN_PASSWORD",),
    ),
    Family(
        # The exact shape resolve_env_settings emits on a cast failure. The producer is fixed too, but
        # the redactor is the backstop for every producer nobody has enumerated, so it must catch it.
        name="quoted_env_value_echo",
        line="setting 'password' (env 'MEFOR_VALUE_PW'='pw-C4st_Val-66'): bad",
        secret="pw-C4st_Val-66",
        patterns=("_MEFOR_SECRET",),
    ),
    # --- families that survived VERBATIM at ebdfa44a6 (BACKLOG #1183, ASVS packet C) ---------------
    # The engine's OWN credential vocabulary is snake_case, and ``\b`` does not fire after an
    # underscore, so a label like ``ad_bind_password=`` never reached the keyword at its tail. Measured
    # leaking verbatim: ``client_secret``, ``bearer_token``, ``basic_password``, ``ad_bind_password``,
    # ``tls_key_password`` and ``vault_token`` — five of the six are real identifiers in this tree.
    # ONE family per widened pattern, because that is what the mutation fixture below can prove.
    Family(
        name="snake_case_credential_label",
        line="ldap bind failed ad_bind_password=pw-Ad_Bind-77 for svc",
        secret="pw-Ad_Bind-77",
        patterns=("_CREDENTIAL_KV",),
    ),
    Family(
        name="snake_case_token_label",
        line="rest connector configured bearer_token=tk-Rest_Tok-88",
        secret="tk-Rest_Tok-88",
        patterns=("_BEARER",),
    ),
    # --- key material: the five names the label-prefix widening still could not reach (#1475) -------
    # No shipped pattern carried these: "key" is ordinary vocabulary and is deliberately absent from
    # ``_CREDENTIAL_KV``, and ``_BEARER``'s ``api[_-]?key`` cannot fire on ``intake_api_key_next``
    # because "_next" follows. FIVE families over FOUR alternates -- one per distinct REACH PATH, which
    # is the granularity the mutation fixture below can prove. ``prefixed_private_key_material`` is not
    # a fifth alternate; it is the only fixture that isolates ``_LABEL_PREFIX`` composing with
    # ``_KEY_MATERIAL``, since the other family covered by two patterns declares both.
    Family(
        name="private_key_material",
        line="signing setup private_key=pk-Priv_Key-33 for IB_ACME_ADT",
        secret="pk-Priv_Key-33",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        # The label prefix carries this one: the module has no ``smart_private_key`` alternate.
        name="prefixed_private_key_material",
        line="smart backend smart_private_key=pk-Sm4rt_Key-11 configured",
        secret="pk-Sm4rt_Key-11",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        name="store_encryption_key",
        line="store opened encryption_key=ek-Enc_Key-44 active",
        secret="ek-Enc_Key-44",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        # A COMMA-JOINED list (``store/keyprovider.py::_split_retired``). Its pattern admits commas so
        # the whole list goes, not just the first element -- the sentinel here is the LAST element,
        # which a comma-terminated value class would have printed verbatim.
        name="retired_encryption_keys_list",
        line="rotation ready encryption_keys_retired=k1-Ret_A-01,k2-Ret_B-02,k3-Ret_C-03 done",
        secret="k3-Ret_C-03",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        name="intake_api_key_rotation_partner",
        line="listener armed intake_api_key_next=nk-N3xt_Key-22 pending",
        secret="nk-N3xt_Key-22",
        patterns=("_KEY_MATERIAL",),
    ),
    Family(
        # A SCREAMING_SNAKE key label, declaring ``_KEY_MATERIAL`` ALONE. Measured 2026-09-06 with a
        # mutation harness: dropping the case fold from ``_KEY_MATERIAL`` left this whole file green
        # without this row. ``mefor_env_value`` is the only other family reaching an upper-case key
        # label, and its comment says outright that it declares ``_KEY_MATERIAL`` *because* the pattern
        # folds case -- but it declares ``_MEFOR_SECRET`` too, and the mutation fixture disables both
        # at once, so it could not tell a folding pattern from a non-folding one. This row can.
        # ``ENCRYPTION_KEYS_RETIRED`` rather than a shorter label so the folded reach also crosses the
        # ``(?:s_retired)?`` tail of the factored alternate.
        name="screaming_snake_key_material",
        line="rotation ready ENCRYPTION_KEYS_RETIRED=ek-Upr_Key-12 pending",
        secret="ek-Upr_Key-12",
        patterns=("_KEY_MATERIAL",),
    ),
)


#: Settings the ENGINE'S OWN classifier calls credentials that :func:`redact_log_line` deliberately
#: does NOT redact, each with the reason it is out.
#:
#: This table is the point of BACKLOG #1475. It converts "the redactor's credential vocabulary is
#: hand-chosen" from a standing defect into a reviewed statement, and
#: ``test_every_engine_credential_setting_is_redacted_or_excluded`` below goes red the day someone adds
#: a credential setting this module cannot see.
#:
#: ALL SIX ARE THE USERNAME CLASS, and they are out on measured grounds rather than on taste:
#:
#: 1. **The widening buys nothing.** Every string literal the engine passes to a logging call or an
#:    exception constructor was extracted by AST -- 5,826 across 268 modules -- and a candidate username
#:    pattern shaped exactly like ``_CREDENTIAL_KV`` fired **zero** times. The shipped
#:    ``_CREDENTIAL_KV`` fired **4** times on the same corpus in the same run, so the instrument works;
#:    a dead needle returned 0, so the corpus was read. Re-measured 2026-09-06.
#: 2. **It reaches the wrong shape anyway.** A ``label=value`` rule does not match how a username
#:    actually leaks: ``Login failed for user 'svc'`` (ODBC prose), ``UID=svc;PWD=`` (a different
#:    keyword), ``CN=svc,OU=`` (a directory DN), the engine's own ``actor=`` audit field, or userinfo
#:    inside a URL.
#: 3. **The engine already ruled on this class at the layer that owns it.**
#:    ``messagefoundry/redaction.py`` scrubs multi-token name runs and states its own residual outright
#:    -- "the residual is now an adversarially-crafted *single-token* ... identifier" (:16, :69). A
#:    username IS a single-token identifier. ``docs/PHI.md`` says the same from the other end: the
#:    forwarded log stream "still carries usernames", and that is its stated reason for gating the
#:    off-box hop. Scrubbing usernames here would contradict a documented position two layers deep.
#:
#: THE CONSEQUENCE IS WRITTEN DOWN RATHER THAN LEFT IMPLIED: a support bundle and ``GET /logs/tail``
#: can carry an operator username. ``messagefoundry support-bundle --help`` and ``docs/PHI.md`` stream
#: 14 both say so, so no reader is told the archive is secret-free while the engine's own classifier
#: disagrees.
EXCLUDED_FROM_REDACTION: dict[str, str] = {
    "username": "username class: the generic principal setting",
    "basic_user": "username class: HTTP Basic principal",
    "credential_username": "username class: Windows/UNC share principal (ADR 0132)",
    "http_auth_user": "username class: HTTP Digest/NTLM principal",
    "proxy_user": "username class: forward-proxy principal (ADR 0126)",
    "ws_username": "username class: WS-Security UsernameToken principal (ADR 0015)",
}


def _applied_pattern_names() -> set[str]:
    """Every module-level pattern name USED inside ``redact_log_line``, derived by AST.

    Reading the function body rather than the module namespace is what makes this a domain rather than
    a list: a pattern defined and never applied cannot silently count as coverage, and a pattern applied
    without a fixture cannot hide."""
    tree = ast.parse(inspect.getsource(redact_mod))
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "redact_log_line"
    )
    module_patterns = {
        name for name, value in vars(redact_mod).items() if isinstance(value, re.Pattern)
    }
    return {
        node.id
        for node in ast.walk(func)
        if isinstance(node, ast.Name) and node.id in module_patterns
    }


def test_the_family_table_covers_every_applied_pattern() -> None:
    """Every pattern redact_log_line applies is claimed by a family or named as a non-secret."""
    applied = _applied_pattern_names()
    # Positive control: the derivation must actually find patterns. A silently-empty domain would make
    # every assertion below vacuously true, which is the failure this whole file exists to prevent.
    assert len(applied) >= 5, f"AST derivation found only {sorted(applied)} -- instrument is broken"

    claimed = {name for fam in FAMILIES for name in fam.patterns}
    unclaimed = applied - claimed - NOT_A_SECRET_PATTERN
    assert not unclaimed, (
        f"applied by redact_log_line but no secret family covers it: {sorted(unclaimed)}"
    )

    # A family must not claim a pattern the redactor never applies -- that is coverage on paper only.
    stale = claimed - applied
    assert not stale, f"declared by a family but never applied: {sorted(stale)}"

    # The exemption set is exact, so widening it is a visible edit rather than a quiet one.
    assert {"_LEADING_TS"} == NOT_A_SECRET_PATTERN


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_no_family_secret_is_reachable_by_the_long_base64_backstop(fam: Family) -> None:
    """A family whose own pattern is not the backstop must not be redactable BY the backstop.

    This is the control that makes every other assertion here mean something. The bearer defect went
    green for months because the suite's chosen token happened to be pure alphanumeric and the sweep
    at ``_LONG_B64`` caught it, so the test could not tell a working pattern from a broken one."""
    if "_LONG_B64" in fam.patterns:
        pytest.skip("this family's declared pattern IS the long-base64 backstop")
    assert not redact_mod._LONG_B64.search(fam.secret), (
        f"{fam.name}: the sentinel {fam.secret!r} is reachable by the long-base64 sweep, so a green "
        "on this family would prove nothing about its own pattern -- pick a token with a hyphen "
        "and an underscore"
    )


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_every_secret_family_value_is_redacted(fam: Family) -> None:
    """The value must not survive redact_log_line, and the reader must see redaction happened."""
    out = redact_log_line(fam.line)
    assert fam.secret not in out, f"{fam.name}: secret survived redaction -- got {out!r}"
    assert REDACTION_PLACEHOLDER in out, f"{fam.name}: nothing was marked redacted -- got {out!r}"


@pytest.mark.parametrize("fam", FAMILIES, ids=lambda f: f.name)
def test_each_family_survives_when_its_own_patterns_are_disabled(
    fam: Family, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the family's declared patterns disabled, the secret MUST leak.

    A pass here means the declared patterns are the ones doing the work. A failure means something
    else in the chain -- the shared PHI pass, the long-base64 sweep, another secret pattern -- is
    covering this family, so the family's own green is not evidence about its own pattern."""
    for name in fam.patterns:
        monkeypatch.setattr(redact_mod, name, NEVER_MATCHES)
    out = redact_log_line(fam.line)
    assert fam.secret in out, (
        f"{fam.name}: disabling {list(fam.patterns)} did NOT make the secret leak -- something else "
        f"is covering it, so this family proves nothing about its declared pattern. Got {out!r}"
    )


#: Diagnostics carrying no credential, which the credential patterns must NOT eat. Over-redaction is
#: the safe direction for a file that leaves the box, but not when it costs an operator the message
#: telling them what to fix.
#:
#: The first two lines are the ONLY ones that discriminate on the ``_AUTH_SCHEME`` word set, and that
#: was measured rather than assumed. "basic" and "digest" are ordinary configuration vocabulary in this
#: engine -- ``transports/http_auth.py`` raises "oauth2_auth_style must be 'basic' or 'post'" and
#: ``transports/soap.py`` raises "ws_password_type must be 'text'" -- but BOTH of those real
#: strings quote the word, so ``\s+`` cannot match and they survive a wide pattern and a narrow one
#: alike. Using them as the guard would have looked like coverage and tested nothing. Run against the
#: widened ``(bearer|basic|digest)`` alternative, the first two lines below are eaten and the real
#: engine strings are not, which is why the fixture is written this way.
ORDINARY_DIAGNOSTICS = (
    "falling back to basic auth for this hop",
    "server offered digest challenge, retrying",
    "oauth2_auth_style must be 'basic' or 'post', got 'bogus'",
    "SOAP ws_password_type must be 'text' (ADR 0015, BACKLOG #1171)",
    "INFO engine started on port 8765",
    "connection IB_DEMO_ADT bound, password rotation scheduled",
    # The label-prefix widening (BACKLOG #1183) reaches a credential word at the TAIL of a snake_case
    # label. These two carry the word in the MIDDLE, where the trailing "\b" cannot fire, so a path
    # and a mode name survive — the widening must not turn a filename into a redaction.
    "password_file=/etc/mefor/pw.txt",
    "ws_password_type=text on the SOAP hop",
    # Three lines the key-material pattern (BACKLOG #1475) must leave alone: a header NAME, a PATH and
    # a REFERENCE. Why it uses literal alternates rather than a general rule is stated once, on
    # ``_KEY_MATERIAL`` in ``messagefoundry/support/redact.py``. These pin the line survives INTACT;
    # ``test_the_key_material_pattern_spares_the_engines_non_secret_siblings`` pins the reason.
    "intake_api_key_header=x-acme-key on the listener",
    "private_key_file=/etc/mefor/sign.pem loaded",
    "encryption_key_ref=vault-kv-store-dek resolved",
)


@pytest.mark.parametrize("line", ORDINARY_DIAGNOSTICS)
def test_ordinary_engine_diagnostics_are_not_eaten_by_the_credential_patterns(line: str) -> None:
    """A diagnostic that carries no credential must survive intact."""
    assert redact_log_line(line) == line, (
        f"a credential pattern ate an ordinary diagnostic: {line!r} -> {redact_log_line(line)!r}"
    )


def test_the_label_prefix_repetition_stays_bounded() -> None:
    """An UNBOUNDED label prefix is quadratic in line length, on attacker-influenceable log text.

    ``_`` suppresses ``\\b``, but "." and "-" do not, so an N-segment dotted or hyphenated run gives the
    regex N start positions and the group re-walks O(N) segments from each. Measured over 20 passes of
    one ~6 KB run: 1.5 ms before the widening, **827 ms with ``*``**, 11 ms at ``{0,6}``. Base64url uses
    "-", so a JWT echoed into a log line is exactly that shape, and both surfaces this module backstops
    would carry the cost.

    Pinned structurally rather than by a stopwatch: a timing assertion on a shared CI runner flakes, and
    the property that matters is that a bound EXISTS. The value is free to move.
    """
    assert re.fullmatch(r"\(\?:\[A-Za-z0-9\]\+\[\._-\]\)\{0,\d+\}", redact_mod._LABEL_PREFIX), (
        f"_LABEL_PREFIX is {redact_mod._LABEL_PREFIX!r} -- it must carry an explicit {{0,N}} bound. "
        "With '*' or '+' the two credential patterns become quadratic in line length (827 ms on one "
        "6 KB hyphen run, against 1.5 ms before the widening)."
    )
    # And the bound must still reach the labels it was added for -- a bound low enough to be safe and
    # too low to be useful would pass the assertion above while silently reverting the fix.
    for label in ("ad_bind_password", "tls_key_password", "client_secret", "bearer_token"):
        assert REDACTION_PLACEHOLDER in redact_log_line(f"{label}=pw-B0und_Chk-99")


#: Patterns whose case fold is scoped to an inline ``(?i:...)`` rather than set for the whole regex.
#: The set is exact, so scoping a fourth pattern is a deliberate edit that also lands in the guard.
SCOPED_CASE_FOLD_PATTERNS = ("_BEARER", "_CREDENTIAL_KV", "_KEY_MATERIAL")

#: Lines the fold guard below runs in four case spellings each. Built from the fixtures this file
#: already maintains, so it widens automatically as families and diagnostics are added, plus the
#: label shapes that only ``_BEARER``'s second alternation reaches.
_CASE_FOLD_CORPUS: tuple[str, ...] = (
    *(fam.line for fam in FAMILIES),
    *ORDINARY_DIAGNOSTICS,
    "upstream sent Authorization: Bearer sk-live-AbCdEf_1234-XYZ",
    "upstream sent Authorization: Basic sk-live-AbCdEf_1234-XYZ",
    "upstream sent Authorization: Digest sk-live-AbCdEf_1234-XYZ",
    "a.b.c.d.e.f.encryption_keys_retired=k1-Ret_A-01,k2-Ret_B-02",
    "a-b-c-d-e-f-private_key=pk-Priv_Key-33",
    "svc_client_secret='sc-V4ult_Val-44';UID=svc",
)


@pytest.mark.parametrize("name", SCOPED_CASE_FOLD_PATTERNS)
def test_a_scoped_case_fold_matches_exactly_what_a_global_one_would(name: str) -> None:
    """Scoping ``(?i)`` down to ``(?i:...)`` is an OPTIMIZATION, so it must change no match.

    Three patterns fold case on an alternation of literal keywords instead of on the whole regex,
    because a global fold also folds the scanned ``_LABEL_PREFIX`` class and costs 18 to 30 percent for
    nothing. The reasoning and the numbers are on ``_BEARER`` in the module.

    THE CONTROL IS THE PATTERN'S OWN SOURCE RECOMPILED WITH ``re.IGNORECASE``, which is the thing the
    scoped form is claiming to be equivalent to. That makes this a structural guard rather than an
    enumeration: it covers every ``(?i:...)`` site at once -- ``_BEARER`` has TWO, and its second one
    is the load-bearing auth-scheme group -- and it covers the fourth site the day someone adds one.
    Nine hand-picked spellings would cover only the sites that exist today.

    THE HAZARD IT EXISTS FOR IS A PARTIAL EDIT. With one global flag, the fold could not be half
    removed. As a local token repeated per alternation, a tidy-up can drop it from one site and leave
    the others, and the shipped fixtures cannot see that: the family covering the auth-scheme line
    declares ``_AUTH_SCHEME`` alongside ``_BEARER``, so it stays green on the other pattern's work --
    this file's own "green a DIFFERENT pattern bought" failure, one layer down.
    """
    scoped: re.Pattern[str] = getattr(redact_mod, name)
    globally_folded = re.compile(scoped.pattern, re.IGNORECASE)

    # Positive control: a corpus that never exercises a case difference would make this vacuous.
    assert any(line != line.upper() for line in _CASE_FOLD_CORPUS)

    for line in _CASE_FOLD_CORPUS:
        for variant in (line, line.upper(), line.lower(), line.title()):
            assert [(m.span(), m.group(1)) for m in scoped.finditer(variant)] == [
                (m.span(), m.group(1)) for m in globally_folded.finditer(variant)
            ], (
                f"{name}: the scoped (?i:...) does not match what a global (?i) would, on {variant!r}. "
                "A fold has been dropped from one alternation, or added to a span that changes a match."
            )


@pytest.mark.parametrize("scheme", ("bearer", "Bearer", "basic", "Basic", "digest", "Digest"))
def test_the_bearer_pattern_folds_case_on_the_auth_scheme_word(
    scheme: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_BEARER``'s optional ``(?:bearer|basic|digest)\\s+`` group must consume the auth scheme.

    THIS IS NOT THE FOLD GUARD -- ``test_a_scoped_case_fold_matches_exactly_what_a_global_one_would``
    is, and it covers this group's ``(?i:...)`` along with every other. This one covers what an
    equivalence check structurally cannot: DELETING the scheme group leaves the scoped and the globally
    folded spellings equivalent to each other, and leaks the credential. Without the group, ``\\S+``
    matches the scheme WORD rather than the token, so "Authorization: Bearer <tok>" redacts "Bearer"
    and prints <tok>. That is BACKLOG #1183's original defect.

    NOTHING ELSE IN THIS FILE CAN SEE THAT EITHER. ``authorization_bearer_header`` declares
    ``_AUTH_SCHEME`` beside ``_BEARER``, so it stays green on the other pattern's work -- this file's
    own "green a DIFFERENT pattern bought" failure, one layer down. So ``_AUTH_SCHEME`` is disabled
    here and ``_BEARER`` has to do the whole job alone.

    ONE LOWERCASE AND ONE CAPITALISED SPELLING PER SCHEME WORD, and each pair has a job: the lowercase
    proves the word is still IN the alternation, the capitalised proves the group folds. Further
    spellings of the same word (BEARER, BeArEr) cannot fail independently of the pair, so they would be
    one case wearing three names.
    """
    monkeypatch.setattr(redact_mod, "_AUTH_SCHEME", NEVER_MATCHES)
    secret = "sk-live-AbCdEf_1234-XYZ"
    out = redact_log_line(f"upstream sent Authorization: {scheme} {secret}")
    assert secret not in out, (
        f"{scheme}: the credential survived _BEARER with _AUTH_SCHEME disabled, so the scheme group is "
        f"not folding case -- it matched the scheme word as the value instead. Got {out!r}"
    )
    assert REDACTION_PLACEHOLDER in out, f"{scheme}: nothing was marked redacted -- got {out!r}"


#: A sentinel carrying a hyphen AND an underscore, so ``_LONG_B64`` cannot reach it. Without that the
#: derived test below would score a name as covered on the strength of the backstop sweep -- the exact
#: false green this file was built to make impossible. The property is ASSERTED in the derived test
#: rather than only claimed here, the same way the Family sentinels are checked above.
_REGISTRY_SENTINEL = "zz-Sekr3t_Val-99"


def _engine_credential_settings() -> set[str]:
    """Every setting name the ENGINE classifies as a credential, read from the engine.

    Two registries, because the engine keeps two and they do not agree:
    ``config/wiring.py::_SECRET_SETTING_KEYS`` is the connector-settings set ``/metadata`` redacts, and
    ``config/settings.py::_FILE_SECRET_KEYS`` is the service-settings set that must live in the
    environment rather than the config file. ``encryption_key``, ``encryption_keys_retired``,
    ``ad_bind_password``, ``oidc_client_secret`` and ``email_password`` are in the second and not the
    first, so reading either one alone is a domain narrower than the engine's own belief."""
    from messagefoundry.config.settings import _FILE_SECRET_KEYS
    from messagefoundry.config.wiring import _SECRET_SETTING_KEYS

    return set(_SECRET_SETTING_KEYS) | {key for _section, key in _FILE_SECRET_KEYS}


def test_every_engine_credential_setting_is_redacted_or_excluded() -> None:
    """THE VOCABULARY IS DERIVED FROM THE ENGINE, NOT HAND-CHOSEN HERE (BACKLOG #1475).

    Before this guard, ``support/redact.py`` picked its credential words by hand. That is the
    narrow-domain defect ``test_connection_factory_redaction_domain.py`` records failing five times on
    the sibling surface, and it fails silently in the one direction that matters: a credential setting
    the redactor cannot see does not error, it just prints.

    So the domain is read from the engine's own two registries, and every name in it must be either
    redacted by ``redact_log_line`` or carry a reason in :data:`EXCLUDED_FROM_REDACTION`.

    Measured 2026-09-06 on the merged tree, with ``_SECRET_SETTING_KEYS | _FILE_SECRET_KEYS`` at 30
    names: 27 survived verbatim before the snake_case label prefix, 11 after it, and 6 after the
    key-material pattern -- and those 6 are the whole of the username class, which is out on the
    grounds recorded above the table.

    THE ASSERTION IS TWO-SIDED ON PURPOSE. A one-sided "everything leaked is excused" version goes
    green forever once the table is wide enough, and an exclusion that has quietly become false is a
    worse record than no record: it tells a reader the engine leaks something it now scrubs."""
    names = _engine_credential_settings()

    # Positive control on the derivation itself. A registry import that silently returned an empty or
    # tiny set would make every assertion below vacuously true.
    assert len(names) >= 25, (
        f"the engine's credential registry read as {sorted(names)} -- too small"
    )

    # And on the sentinel: were it reachable by the long-base64 sweep, every name below would score as
    # covered on the backstop's work rather than on its own pattern's.
    assert not redact_mod._LONG_B64.search(_REGISTRY_SENTINEL), (
        f"{_REGISTRY_SENTINEL!r} is reachable by the long-base64 sweep, so this test would measure the "
        "backstop instead of the credential patterns -- give it a hyphen and an underscore"
    )

    leaked = {
        name
        for name in names
        if _REGISTRY_SENTINEL
        in redact_log_line(f"connect failed {name}={_REGISTRY_SENTINEL} for endpoint")
    }

    unexplained = leaked - set(EXCLUDED_FROM_REDACTION)
    assert not unexplained, (
        "the engine classifies these settings as credentials, but redact_log_line prints their values "
        f"verbatim and no reason is recorded for it: {sorted(unexplained)}. A support bundle and GET "
        "/logs/tail both pass through this module, so a hole lands on both. Either widen the module or "
        "add the name to EXCLUDED_FROM_REDACTION with the reason it is deliberately out."
    )

    stale = set(EXCLUDED_FROM_REDACTION) - leaked
    assert not stale, (
        f"EXCLUDED_FROM_REDACTION excuses these, but redact_log_line already redacts them: "
        f"{sorted(stale)}. A stale exclusion is a false record -- it tells a reader the engine leaks "
        "something it does not. Remove the entry."
    )

    # And the table must not invent a name. An entry outside the registry is excusing nothing, and it
    # would survive the registry dropping the setting entirely.
    unknown = set(EXCLUDED_FROM_REDACTION) - names
    assert not unknown, (
        f"EXCLUDED_FROM_REDACTION names settings the engine's registries do not carry: "
        f"{sorted(unknown)}. The table must excuse real names, or it excuses nothing."
    )


def test_the_excluded_settings_are_the_username_class_the_engine_itself_names() -> None:
    """The exclusion is a CLASS THE ENGINE ALREADY NAMES, not a list of whatever happened to leak.

    Pinned separately from the derived test because the two fail for different reasons: that one dies
    if the domain regresses, this one dies if the exclusion drifts off the class the ruling covers.
    Nothing but a username is excusable here -- a password, token or key that ends up in this table is
    a hole being annotated rather than fixed, and it would pass the derived test above.

    MEMBERSHIP, NOT A SUBSTRING, AND THE DIFFERENCE IS THE WHOLE ASSERTION.
    ``wiring._NON_ROTATABLE_SECRET_SETTING_KEYS`` is the engine's own statement of exactly this class
    -- its docstring calls it the single source of truth for "settings keys that are IDENTIFIERS
    (usernames), not rotatable credentials" -- and measured 2026-09-06 it is character-for-character
    this table's key set. An earlier version of this test asked ``"user" in name`` instead, which
    ACCEPTS ``db_user_password``, ``user_token`` and ``superuser_api_key``: a future maintainer could
    excuse a leaked password by writing a username reason beside it and pass both guards. That is the
    falsely-accepting checker this test exists to be, so it reads the engine's set."""
    from messagefoundry.config.wiring import _NON_ROTATABLE_SECRET_SETTING_KEYS

    assert set(EXCLUDED_FROM_REDACTION) == set(_NON_ROTATABLE_SECRET_SETTING_KEYS), (
        "the settings this module deliberately does not redact must be exactly the identifier class "
        "the engine names in _NON_ROTATABLE_SECRET_SETTING_KEYS. Excused here but not there: "
        f"{sorted(set(EXCLUDED_FROM_REDACTION) - set(_NON_ROTATABLE_SECRET_SETTING_KEYS))}; named "
        f"there but redacted here: {sorted(set(_NON_ROTATABLE_SECRET_SETTING_KEYS) - set(EXCLUDED_FROM_REDACTION))}"
    )
    for name, reason in EXCLUDED_FROM_REDACTION.items():
        assert reason.startswith("username class:"), f"{name}: reason does not state the class"


def test_the_key_material_pattern_spares_the_engines_non_secret_siblings() -> None:
    """The five names #1475 widened onto have non-secret siblings one word away.

    The reason literal alternates were chosen over a general rule is stated ONCE, on ``_KEY_MATERIAL``
    in ``messagefoundry/support/redact.py``; this asserts the property that argument turns on rather
    than restating it. ``intake_api_key_header`` is the sharpest case, and this test pins WHY it
    survives -- the engine does not classify it as a credential -- where ORDINARY_DIAGNOSTICS pins only
    that the line comes back unchanged.

    THE SENTINEL VALUES DIFFER FROM THE FAMILY FIXTURES ON PURPOSE. These lines are bare
    ``label=value`` with no surrounding words, so they also cover start-of-string anchoring, which no
    Family line reaches."""
    from messagefoundry.config.wiring import _SECRET_SETTING_KEYS

    assert "intake_api_key_header" not in _SECRET_SETTING_KEYS  # the engine's own classification
    for sibling in ("intake_api_key_header", "private_key_file", "encryption_key_ref"):
        line = f"{sibling}=nonsecret-value_01 in use"
        assert redact_log_line(line) == line, f"{sibling} was eaten by the key-material pattern"

    # And the targets themselves must still go. Assert the VALUE IS ABSENT, not merely that a
    # placeholder appeared: a value class narrowed to stop at "-" leaves the secret's tail on the line
    # beside a placeholder, which a placeholder-only assertion reports as a pass.
    for target in (
        "private_key",
        "smart_private_key",
        "encryption_key",
        "encryption_keys_retired",
        "intake_api_key_next",
    ):
        out = redact_log_line(f"{target}=km-K3y_Mat-77")
        assert "km-K3y_Mat-77" not in out, f"{target}: the value survived -- got {out!r}"
        assert REDACTION_PLACEHOLDER in out, f"{target}: nothing was marked redacted -- got {out!r}"


def test_redactor_is_the_backstop_for_both_named_surfaces() -> None:
    """The support archive and the log-tail route both go through this module, so a hole lands twice.

    Asserted by reading the two sources rather than by trusting the docstrings, so moving either call
    off the shared redactor reds this test instead of quietly halving the coverage."""
    pkg = pathlib.Path(redact_mod.__file__).resolve().parent.parent
    bundle = (pkg / "support" / "bundle.py").read_text(encoding="utf-8")
    api = (pkg / "api" / "app.py").read_text(encoding="utf-8")
    assert "from messagefoundry.support.redact import redact_log_text" in bundle
    assert "from messagefoundry.support.redact import redact_log_line" in api
