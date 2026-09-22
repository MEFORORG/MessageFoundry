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

Three failures this file is built to make impossible. The first two were measured at 4633a295; the
third was added at BACKLOG #1547 and has its own measurements below:

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

3. **A COST domain narrower than the surface**, added at BACKLOG #1547 and the reason this file now
   reads two modules rather than one. A credential pattern can be correct and still be a denial of
   service: an unbounded repetition over a class holding "." or "-" is quadratic in line length, on
   log text an attacker can influence. The guard against that read ONE named pattern, ``_LABEL_PREFIX``
   -- and ``_DSN_PASSWORD`` shipped the identical defect beside it, in this module AND in the
   write-time copy at ``messagefoundry/secretscrub.py``, for as long as the narrow guard existed. So
   the cost guard now derives its subjects the way the coverage guard already did, over BOTH copies of
   the vocabulary: ``test_every_applied_credential_pattern_has_a_contained_scan_prefix`` for the
   structural property and ``test_the_dsn_scan_grows_linearly_in_line_length`` for the growth it is
   bought for. Only the COST guards read ``secretscrub``; the coverage and fixture guards above stay
   scoped to ``support/redact``, which has its own suite in ``tests/test_logging_credential_scrub.py``.

   A COST GUARD NEEDS A COVERAGE ARM BESIDE IT, and #1547 paid for that lesson TWICE on this one
   pattern. The first fix bounded the repetition, which made the cost guard green by making the pattern
   refuse to match a DSN behind a 64-character run -- a credential published in full, in both copies,
   with every cost assertion passing. ``test_the_dsn_scan_still_reaches_every_scheme_shape_that_matters``
   is the arm that catches a cost bought that way; do not leave a cost guard without one.

   THE SECOND TIME, THAT COVERAGE ARM EXISTED AND STILL MISSED IT, which is the sharper half of the
   lesson. The anchored fix that replaced the bound kept a ``[a-z]`` head on the scheme, and every
   entry of ``_DSN_SCHEMES_THAT_MUST_REDACT`` began with a letter -- so a DSN behind a digit-, "+"-,
   "."- or "-"-headed run lost its match on both surfaces while the table it was supposed to be caught
   by stayed green. A table of shapes somebody thought of cannot fail for a shape nobody thought of.
   ``test_the_dsn_head_redacts_everything_both_earlier_heads_did`` is the answer to that one: it is a
   DIFFERENTIAL against the spellings this pattern replaced, so it fails on any narrowing rather than
   on the narrowings a fixture author anticipated. Prefer that shape wherever a change claims to widen
   what a pattern catches.

The sentinel values are invented HERE, never derived from the code under test. They are synthetic and
carry no real credential, host or site.
"""

from __future__ import annotations

import ast
import inspect
import math
import pathlib
import re
import re._constants as sre_constants
import re._parser as sre_parser
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from types import ModuleType
from typing import Any

import pytest
from _ast_sites import named_func

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
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


# --- BACKLOG #1685: a QUOTED credential value, whose tail the shipped pattern wrote to the bundle ---
#
# A value is quoted PRECISELY so it may carry the characters that would otherwise end it -- ";", "="
# and spaces -- and those are what ``_CREDENTIAL_KV``'s value class stopped at. So the shipped pattern
# redacted the HEAD of a quoted password and wrote the tail into the support archive and
# ``GET /logs/tail``. Measured against this module at 1aa2d6a1b:
#
#   PWD={pw-A;B}                     ->  PWD=[REDACTED];B}
#   ad_bind_password='pw-A pw-B'     ->  ad_bind_password=[REDACTED] pw-B'
#
# THE SENTINELS ARE SPLIT IN TWO ON PURPOSE. A family names ONE ``secret``; the defect printed the
# LATER piece, so a family naming the whole value would have gone green throughout. Both halves carry a
# hyphen AND an underscore so ``_LONG_B64`` cannot reach them -- this surface has a backstop the
# write-time one does not, and a sentinel the backstop covers proves nothing about ``_CREDENTIAL_KV``.


@dataclass(frozen=True)
class QuotedValue:
    """One log line carrying a quoted credential, split into the pieces none of which may survive.

    ``survives`` is what the redaction must NOT eat. Over-redaction is the safe direction for a file
    that leaves the box, but it is not free: which server the failing connection named is most of what
    the reader opened the bundle for."""

    name: str
    line: str
    fragments: tuple[str, ...]
    survives: tuple[str, ...]


def odbc_line(value: str) -> str:
    """An ODBC connection-string log line whose password is ``value``, brace-quoted.

    ``value`` is already ODBC-ENCODED, so a doubled ``}}`` here means one ``}`` in the password."""
    return "odbc conn Driver={ODBC Driver 18};UID=svc;PWD={" + value + "};Server=db-1.invalid"


#: What survives an ODBC line: the server, and a brace-quoted value under a NON-credential keyword.
_ODBC_SURVIVES = ("Driver={ODBC Driver 18}", "Server=db-1.invalid")

QUOTED_VALUES: tuple[QuotedValue, ...] = (
    QuotedValue(
        "brace_semicolon",
        odbc_line("pw-Semi_A-13;pw-Semi_B-14"),
        ("pw-Semi_A-13", "pw-Semi_B-14"),
        _ODBC_SURVIVES,
    ),
    QuotedValue(
        "brace_space",
        odbc_line("pw-Spc_A-15 pw-Spc_B-16"),
        ("pw-Spc_A-15", "pw-Spc_B-16"),
        _ODBC_SURVIVES,
    ),
    QuotedValue(
        # A REGRESSION GUARD, NOT A REPRODUCTION, recorded because the difference is invisible from the
        # table. The pre-fix class admitted "=", so this row went green before the fix; it proves only
        # that the new alternates did not narrow it.
        "brace_equals",
        odbc_line("pw-Eq_A-17=pw-Eq_B-18"),
        ("pw-Eq_A-17", "pw-Eq_B-18"),
        _ODBC_SURVIVES,
    ),
    QuotedValue(
        "brace_comma",
        odbc_line("pw-Cma_A-19,pw-Cma_B-20"),
        ("pw-Cma_A-19", "pw-Cma_B-20"),
        _ODBC_SURVIVES,
    ),
    QuotedValue(
        # THE ROW THAT TELLS A CORRECT FIX FROM A NAIVE ONE; the reasoning is on the test that pins it,
        # ``test_a_first_closing_brace_pattern_would_still_leak_the_doubled_brace_row``.
        "brace_doubled",
        odbc_line("pw-Dbl_A-21}}pw-Dbl_B-23;pw-Dbl_C-24"),
        ("pw-Dbl_A-21", "pw-Dbl_B-23", "pw-Dbl_C-24"),
        _ODBC_SURVIVES,
    ),
    QuotedValue(
        # THE MORE REACHABLE HALF OF THE DEFECT. Brace-quoting rides in on the SQL Server store; a
        # password with a SPACE in it reaches every backend, and this is a real engine setting.
        "single_quoted_space",
        "ldap bind failed ad_bind_password='pw-Sq_A-25 pw-Sq_B-26' for svc",
        ("pw-Sq_A-25", "pw-Sq_B-26"),
        ("ldap bind failed", "for svc"),
    ),
    QuotedValue(
        "double_quoted_space",
        'api tls tls_key_password="pw-Dq_A-27 pw-Dq_B-28" could not open the chain',
        ("pw-Dq_A-27", "pw-Dq_B-28"),
        ("api tls", "could not open the chain"),
    ),
    QuotedValue(
        "single_quoted_semicolon",
        "connect failed password='pw-Qsc_A-29;pw-Qsc_B-30' retrying",
        ("pw-Qsc_A-29", "pw-Qsc_B-30"),
        ("connect failed", "retrying"),
    ),
)


#: The quoted rows as families, so they inherit this file's four parametrized assertions: the backstop
#: cannot reach the sentinel, the value is redacted, the DECLARED pattern is what did it, and the
#: scoped case fold matches a global one. DERIVED rather than restated, so the two cannot drift.
#:
#: ``secret`` is the LAST fragment -- the piece the shipped pattern printed verbatim.
QUOTED_FAMILIES: tuple[Family, ...] = tuple(
    Family(
        name=f"quoted_{case.name}",
        line=case.line,
        secret=case.fragments[-1],
        patterns=("_CREDENTIAL_KV",),
    )
    for case in QUOTED_VALUES
)


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
    *QUOTED_FAMILIES,
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


def _applied_names(
    module: ModuleType, applier: str, select: Callable[[str, object], bool]
) -> set[str]:
    """Every module-level name matching ``select`` that is USED inside ``module.<applier>``, by AST.

    Reading the function body rather than the module namespace is what makes this a domain rather than
    a list: a pattern defined and never applied cannot silently count as coverage, and a pattern applied
    without a fixture cannot hide. Parameterised by module since BACKLOG #1547, because the cost guard
    below has to read the write-time copy of this vocabulary as well as this one.

    ONE WALK, TWO SELECTORS. The patterns and the admission gates are the same question asked of two
    kinds of module-level value, and a second copy of this walk would have to be fixed twice -- a
    divergence between them would be invisible, since each only ever reports about its own kind."""
    tree = ast.parse(inspect.getsource(module))
    func = named_func(tree, applier)
    wanted = {name for name, value in vars(module).items() if select(name, value)}
    return {node.id for node in ast.walk(func) if isinstance(node, ast.Name) and node.id in wanted}


def _applied_pattern_names(module: ModuleType, applier: str) -> set[str]:
    """Every module-level compiled pattern applied inside ``module.<applier>``."""
    return _applied_names(module, applier, lambda _name, value: isinstance(value, re.Pattern))


def _applied_gate_names(module: ModuleType, applier: str) -> set[str]:
    """Every module-level admission-gate tuple read inside ``module.<applier>``.

    A SEVENTH gate added to ``_run`` must widen what reads it, or an assertion over a hand-written
    list of six keeps passing while covering less than it appears to."""
    return _applied_names(
        module,
        applier,
        lambda name, value: name.endswith("_HINT") and isinstance(value, tuple),
    )


def test_the_family_table_covers_every_applied_pattern() -> None:
    """Every pattern redact_log_line applies is claimed by a family or named as a non-secret."""
    applied = _applied_pattern_names(redact_mod, "redact_log_line")
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


@pytest.mark.parametrize("case", QUOTED_VALUES, ids=lambda c: c.name)
def test_no_fragment_of_a_quoted_credential_value_reaches_the_bundle(case: QuotedValue) -> None:
    """EVERY piece of a quoted value must be gone, and the rest of the line must still be there.

    The family assertion above cannot make the first half: it names a single ``secret``, so a pattern
    that replaced the value's head and printed the rest satisfies it for whichever piece it happened to
    name. This surface is the support ARCHIVE and ``GET /logs/tail`` -- a file that leaves the box --
    so the assertion enumerates the fragments instead.

    The second half pulls the other way and is why it shares a test. Over-redaction is the safe
    direction here, but an alternate that ran to end of line on a WELL-FORMED value would pass the
    first half while deleting which server the failing connection named."""
    out = redact_log_line(case.line)

    survivors = [fragment for fragment in case.fragments if fragment in out]
    assert not survivors, f"{case.name}: {survivors} survived a quoted value -- got {out!r}"
    assert REDACTION_PLACEHOLDER in out, f"{case.name}: nothing was marked redacted -- got {out!r}"

    eaten = [context for context in case.survives if context not in out]
    assert not eaten, f"{case.name}: the redaction ate {eaten} -- got {out!r}"


def test_a_first_closing_brace_pattern_would_still_leak_the_doubled_brace_row() -> None:
    """THE CONTROL THAT MAKES THE DOUBLED-BRACE ROW WORTH ITS PLACE.

    ODBC ends a brace-quoted value at the first ``}`` that is not doubled; an interior literal ``}``
    is written ``}}``. The obvious fix -- ``\\{[^}]*\\}`` -- therefore passes every other row in
    :data:`QUOTED_VALUES` and leaks on this one. Built here rather than described in a comment, because
    a fixture whose discriminating power is only claimed is one nobody notices losing.

    The expected leak is DERIVED, not transcribed: a first-brace pattern stops after the head, so
    everything after ``fragments[0]`` survives by construction."""
    case = next(c for c in QUOTED_VALUES if c.name == "brace_doubled")
    naive = re.compile(r"(?i)\b(pwd)\b\s*[:=]\s*\{[^}]*\}")
    naive_out = naive.sub(lambda m: f"{m.group(1)}={REDACTION_PLACEHOLDER}", case.line)

    assert REDACTION_PLACEHOLDER in naive_out, "the naive pattern did not fire at all"
    assert [f for f in case.fragments if f in naive_out] == list(case.fragments[1:]), (
        f"a first-closing-brace pattern was expected to leak every fragment after the head -- "
        f"{naive_out!r}"
    )


def test_an_unclosed_brace_redacts_to_the_end_of_the_line() -> None:
    """A ``{`` this module cannot close must not fall back to printing the password.

    A truncated connection string reaches this surface as readily as a well-formed one -- a driver
    error string is cut off wherever the driver cut it. Dropping back to the plain value class there
    would emit the tail, so the run takes the rest of the line instead. That over-redacts, which is the
    direction a file leaving the box is allowed to fail in."""
    out = redact_log_line("odbc conn UID=svc;PWD={pw-Uncl_A-31;pw-Uncl_B-32")
    assert "pw-Uncl_A-31" not in out
    assert "pw-Uncl_B-32" not in out
    assert REDACTION_PLACEHOLDER in out
    # The line's own prefix survives, so an operator still sees which connection failed.
    assert out.startswith("odbc conn UID=svc;PWD=")


def test_the_quoted_value_repetitions_stay_non_backtracking() -> None:
    """THE READ-TIME COPY OF THE FRAGMENTS NEEDS ITS OWN BOUND GUARD, and this is it.

    ``test_every_applied_credential_pattern_has_a_contained_scan_prefix`` below pins
    ``_LABEL_PREFIX``'s ``{0,N}``, and every other applied pattern's containment, because an unbounded
    repetition a fresh start position can enter is quadratic. This sentence named that guard's narrow
    predecessor until BACKLOG #1547 widened it from one pattern to the derived applied set.

    THE FRAGMENTS BELOW ARE OUT OF THAT GUARD'S REACH, which is why this one is not redundant: they
    are bare pattern-source strings rather than applied ``re.Pattern`` objects, so the derived set
    never sees them. They reach the same property by the other
    route -- a DETERMINISTIC repetition made POSSESSIVE, which cannot re-walk at all -- so what has to
    be pinned is the ``*+``, not a bound. Without this, the read-time copy could be relaxed to a plain
    ``*`` with the whole suite green, and this is the copy that feeds the support archive and
    ``GET /logs/tail``.

    Structural rather than a stopwatch, for the reason the sibling guard already gives: a timing
    assertion on a shared runner flakes, and the property that matters is that the mitigation is
    there."""
    for name in ("_ODBC_BRACED", "_QUOTED_VALUE"):
        fragment = getattr(redact_mod, name)
        assert "*+" in fragment, (
            f"{name} is {fragment!r} -- its repetition must stay POSSESSIVE. A plain '*' re-walks a "
            "value whose closer never arrives, on attacker-influenceable log text."
        )
        assert "*" not in fragment.replace("*+", ""), (
            f"{name} is {fragment!r} -- it grew a repetition that is neither possessive nor bounded."
        )

    # Anti-vacuity: both fragments must still be REACHED, or the assertions above pin dead strings.
    # Taken from the table rather than written fresh, so this cannot go green over a shape the suite
    # does not actually cover.
    for name in ("brace_semicolon", "single_quoted_space"):
        case = next(c for c in QUOTED_VALUES if c.name == name)
        assert REDACTION_PLACEHOLDER in redact_log_line(case.line), name


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


# --- the COST guards: one vocabulary, two copies, every applied pattern ---------------------------
#
# WHY A SECOND KIND OF GUARD AT ALL. Everything above asks whether a pattern REDACTS. These ask what it
# COSTS to ask, which is a security property in its own right on a pass that runs over
# attacker-influenceable log text. A pattern can be perfectly correct and still hand an unauthenticated
# sender a way to hang a worker on first deployment.

#: The credential surfaces the cost guards read: a module, and the function that APPLIES its patterns.
#: BOTH copies, because the defect BACKLOG #1547 fixed shipped in both and a guard reading one of them
#: cannot see the other regress. The pattern set is derived from the applying function by AST, so
#: neither module can grow a pattern these guards do not check.
CREDENTIAL_SURFACES: tuple[tuple[ModuleType, str], ...] = (
    (redact_mod, "redact_log_line"),
    (scrub_mod, "_run"),
)

#: The pattern BACKLOG #1547 replaced, exactly as it shipped. It is the positive control for BOTH cost
#: guards: an instrument that cannot see this one says nothing about the patterns it passes.
_SHIPPED_BEFORE_DSN = r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@"

#: #1547's FIRST anchored spelling, which kept a ``[a-z]`` head on the scheme. Contained and linear,
#: and it silently stopped redacting a DSN whose leading run opens on a digit, "+", "." or "-". Kept as
#: a named subject rather than described, so the differential arm below can compare against the thing
#: itself -- a narrowing is only visible against the spelling that did NOT have it.
_LETTER_HEAD_DSN = r"(?i)(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@"

#: One WORD character, by the definition ``\b`` itself uses. The structural guard turns on whether a
#: character class can end a word, so it asks ``re`` rather than hard-coding a set.
_WORD_CHAR = re.compile(r"\w")

#: Applied patterns whose scan prefix carries an unbounded repetition BY DESIGN, each with the reason
#: it is not the shape the guard catches. Exact and asserted non-stale below, so an entry cannot outlive
#: the pattern that needed it -- an exemption that has quietly become unnecessary is a false record.
SCAN_UNBOUNDED_BY_DESIGN: dict[str, str] = {
    "_LONG_B64": (
        "the backstop sweep. Its run is >= 24 characters of [A-Za-z0-9+/] and a MATCH CONSUMES the "
        "run, so re.sub resumes past it rather than re-entering it from each interior word boundary. "
        "The failing case is a run SHORTER than 24, which is O(1) per start position. Measured over "
        "four adversarial shapes -- a '+' run, a '/' run, three-letter words, and a long '+' tail that "
        "forces the trailing word-boundary assertion to backtrack -- 6.9x to 8.7x the time for 8x the "
        "length, which is linear. Bounding it would split one long run into several placeholders."
    ),
}


def _class_reach(items: Any) -> tuple[bool, bool]:
    """``(admits a word character, admits a non-word character)`` for one parsed character class.

    Anything this cannot enumerate is reported as BOTH, which FLAGS the pattern rather than waving it
    through. That is the only direction an instrument like this may fail in."""
    if any(op == sre_constants.NEGATE for op, _arg in items):
        return (True, True)  # the complement of a small set spans the boundary for every class here
    word = nonword = False
    for op, arg in items:
        if op == sre_constants.LITERAL:
            chars = chr(arg)
        elif op == sre_constants.RANGE:
            low, high = arg
            if high - low > 256:
                return (True, True)
            chars = "".join(chr(point) for point in range(low, high + 1))
        elif op == sre_constants.CATEGORY:
            if arg in (sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_WORD):
                word = True
                continue
            if arg == sre_constants.CATEGORY_SPACE:
                nonword = True
                continue
            return (True, True)
        else:
            return (True, True)
        for char in chars:
            if _WORD_CHAR.fullmatch(char):
                word = True
            else:
                nonword = True
    return (word, nonword)


def _enumerable_class(items: Any) -> frozenset[str] | None:
    """Every character one parsed character class admits, or ``None`` when it cannot be enumerated.

    ``None`` is the cannot-tell answer, and every caller treats it as unsafe -- the same one-way
    failure direction as :func:`_class_reach`."""
    if any(op == sre_constants.NEGATE for op, _arg in items):
        return None
    chars: set[str] = set()
    for op, arg in items:
        if op == sre_constants.LITERAL:
            chars.add(chr(arg))
        elif op == sre_constants.RANGE:
            low, high = arg
            if high - low > 256:
                return None
            chars.update(chr(point) for point in range(low, high + 1))
        else:
            return None  # a CATEGORY (\w, \s, \d) is a set this does not need to reason about
    return frozenset(chars)


def _head_delimiter_class(parsed: Any) -> frozenset[str] | None:
    """The characters a leading ``(?<![...])`` forbids immediately before a match.

    ``None`` when the pattern has no such head, or when the class cannot be enumerated. A
    lookAHEAD is rejected: it constrains what follows a start position, never where one may be."""
    if not len(parsed):
        return None
    op, arg = parsed[0]
    if op != sre_constants.ASSERT_NOT:
        return None
    direction, body = arg
    if direction != -1:
        return None
    items = list(body)
    if len(items) != 1 or items[0][0] != sre_constants.IN:
        return None
    return _enumerable_class(items[0][1])


def _repeat_cannot_restart(body: Any, *, anchored: bool, delimited: frozenset[str] | None) -> bool:
    """Whether an UNBOUNDED repetition over ``body`` is safe to leave in a scan prefix.

    Safe means the engine cannot re-enter it from O(N) start positions. A repetition over a GROUP is
    never safe under either route below: that is the ``(?:[A-Za-z0-9]+[._-])*`` shape
    ``_LABEL_PREFIX``'s bound exists to stop.

    TWO ROUTES REACH THAT PROPERTY, and they attack opposite halves of the O(N) x O(N).

    THE WORD-BOUNDARY ROUTE bounds the START POSITIONS a ``\\b`` head offers: the body must be a
    single character class that does NOT span a word boundary, so a run of it has no interior ``\\b``
    to restart from -- ``[A-Za-z0-9]+`` and ``\\s*`` qualify, ``[a-z0-9+.\\-]*`` does not. It needs
    the ``\\b`` or ``^`` head, because with no head anchor every offset is a start position and even a
    word-only class is quadratic.

    THE DELIMITER ROUTE (BACKLOG #1547) is what ``_DSN_PASSWORD`` uses, and it is why an unbounded
    repetition can be the SAFER spelling. A head ``(?<![C])`` whose class C contains every character
    the repetition admits means a match may not START inside a run of that class: a start is preceded
    by a character outside C, and a walk over C stops at the first character outside C, so the walks
    TILE the line instead of nesting -- O(N) work in total rather than O(N) from each of O(N) offsets.
    (Fixed-width atoms between the head and the repetition shift a walk by at most their own width,
    which is a constant factor and not a second N.) The repetition is then free to be unbounded --
    which matters, because a ``{0,N}`` here bounds the WALK and not the start positions, so it buys
    linearity by silently refusing to match past N characters.

    CONTAINMENT IS NOT CORRECTNESS AND THIS FUNCTION ONLY SEES THE FIRST. ``_DSN_PASSWORD`` once sat at
    ``(?<![a-z0-9+.\\-])([a-z]...``, which satisfies the delimiter route exactly -- and the narrower
    HEAD ATOM meant a start needed the preceding character outside the class and the first character a
    letter, which together hold only at a run's head, so a run opening on a digit or a delimiter
    matched nowhere and the password was published. Passing here has never meant a pattern still
    catches what it used to; ``test_the_dsn_head_redacts_everything_both_earlier_heads_did`` is the arm
    that answers that, and this one must not be read as covering it.
    """
    items = list(body)
    if len(items) != 1 or items[0][0] != sre_constants.IN:
        return False
    run = _enumerable_class(items[0][1])
    if delimited is not None and run is not None and run <= delimited:
        # Both classes sit under the same global fold, so a case-insensitive pattern widens them
        # identically and the subset relation carries.
        return True
    word, nonword = _class_reach(items[0][1])
    return anchored and not (word and nonword)


def _walk_scan_prefix(
    seq: Any, *, anchored: bool, delimited: frozenset[str] | None, seen: bool, found: list[str]
) -> bool:
    """Walk one parsed sequence in order, appending offenders to ``found``.

    Returns whether the sequence REQUIRES a literal character. Once one is required, everything after
    it has left the scan prefix: the engine can only reach it from a start position that already
    matched that literal, so the O(N) multiplier is gone."""
    step = partial(_walk_scan_prefix, anchored=anchored, delimited=delimited, found=found)
    for op, arg in seq:
        if op == sre_constants.LITERAL:
            seen = True
        elif op in (
            sre_constants.MAX_REPEAT,
            sre_constants.MIN_REPEAT,
            sre_constants.POSSESSIVE_REPEAT,
        ):
            low, high, body = arg
            unbounded = high == sre_constants.MAXREPEAT
            safe = _repeat_cannot_restart(body, anchored=anchored, delimited=delimited)
            if not seen and unbounded and not safe:
                found.append(f"{{{low},}} over {list(body)}")
            inner = step(body, seen=seen)
            seen = seen or (low >= 1 and inner)
        elif op == sre_constants.SUBPATTERN:
            seen = step(arg[3], seen=seen)
        elif op == sre_constants.ATOMIC_GROUP:
            seen = step(arg, seen=seen)
        elif op == sre_constants.BRANCH:
            # Every alternative, not the first that matches: a literal is REQUIRED only if all of them
            # require one, and a branch nobody walked is a branch nobody checked.
            required = [step(option, seen=seen) for option in arg[1]]
            seen = bool(required) and all(required)
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            step(arg[1], seen=seen)
    return seen


def _unbounded_scan_repeats(source: str) -> tuple[str, ...]:
    """Every unbounded repetition in ``source``'s SCAN PREFIX -- the span a fresh start position can
    enter before the pattern requires a literal character.

    That span is where a quadratic lives. The engine tries it at every start position the text offers,
    and an unbounded repetition over a class holding "." or "-" re-walks O(N) characters from each one.
    AFTER a required literal there is no such multiplier, which is why ``_MFB64``'s ``[A-Za-z0-9+/=]+``
    and every ``label=VALUE`` value class come back clean and need no excusing.

    The head is read TWICE, once for each route :func:`_repeat_cannot_restart` documents: as a
    ``\\b``/``^`` anchor, and as a ``(?<![C])`` delimiter class."""
    parsed = sre_parser.parse(source)
    head = parsed[0] if len(parsed) else (None, None)
    anchored = head[0] == sre_constants.AT and head[1] in (
        sre_constants.AT_BOUNDARY,
        sre_constants.AT_BEGINNING,
        sre_constants.AT_BEGINNING_STRING,
    )
    found: list[str] = []
    _walk_scan_prefix(
        parsed,
        anchored=anchored,
        delimited=_head_delimiter_class(parsed),
        seen=False,
        found=found,
    )
    return tuple(found)


def test_every_applied_credential_pattern_has_a_contained_scan_prefix() -> None:
    """No applied pattern may leave an unbounded repetition a fresh start position can enter.

    WIDENED FROM ONE NAMED PATTERN TO EVERY APPLIED ONE, IN BOTH COPIES (BACKLOG #1547). This guard
    used to assert only that ``_LABEL_PREFIX`` carried a ``{0,N}``, and ``_DSN_PASSWORD`` sat two
    definitions below it with ``\\b([a-z][a-z0-9+.\\-]*`` -- the same class, the same open scan, the
    same quadratic -- in this module and in ``messagefoundry/secretscrub.py``, for the whole life of
    the narrow guard. A guard over one named pattern cannot see the next one. A guard over the DERIVED
    applied set can, and reds the day either module grows a pattern with that shape.

    CONTAINED, NOT BOUNDED, AND THE WORD IS THE POINT. The first spelling of this guard asserted a
    ``{0,N}``, and a ``{0,63}`` on ``_DSN_PASSWORD`` satisfied it while silently refusing to match a
    DSN glued to a 64-character run -- a credential published in full, bought with a guard that went
    green. A bound on the WALK is one way to contain a scan and it is the lossy one; a ``(?<![C])``
    head that keeps a match from starting inside such a run is the other, and it costs nothing. Both
    routes are spelled out on :func:`_repeat_cannot_restart`.

    STRUCTURAL RATHER THAN A STOPWATCH, for the reason the narrow version already gave: a timing
    assertion on a shared runner flakes, and the property that matters here is that the containment
    EXISTS. ``test_the_dsn_scan_grows_linearly_in_line_length`` is the separate arm that measures the
    growth it is bought for, and
    ``test_the_dsn_scan_still_reaches_every_scheme_shape_that_matters`` is the arm that catches a
    containment bought by refusing to match.
    """
    # POSITIVE CONTROL ON THE INSTRUMENT, one for each shape it has to catch: the scheme class this
    # widening was written for, and the label prefix the narrow version guarded, shown unbounded. A
    # checker that misses these proves nothing about the patterns it passes.
    assert _unbounded_scan_repeats(_SHIPPED_BEFORE_DSN), "the checker cannot see the #1547 pattern"
    assert _unbounded_scan_repeats(r"\b(?:[A-Za-z0-9]+[._-])*(?:password)\b['\"]?[:=]\S+"), (
        "the checker cannot see an unbounded _LABEL_PREFIX, which the narrow guard could"
    )
    # THE DELIMITER ROUTE'S OWN POSITIVE CONTROL. A lookbehind NARROWER than the repetition it heads
    # leaves the class's other characters -- here "." and "-", the two that carry the quadratic --
    # free to start a match mid-run, so it must still be flagged. Without this, the route added for
    # BACKLOG #1547 would wave through any pattern that merely HAS a lookbehind.
    assert _unbounded_scan_repeats(r"(?i)(?<![a-z])([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@"), (
        "a lookbehind that does not cover the repetition's own class is not containment"
    )
    # And a lookAHEAD constrains what FOLLOWS a start position, never where one may be.
    assert _unbounded_scan_repeats(
        r"(?i)(?![a-z0-9+.\-])([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@"
    )
    # NEGATIVE CONTROL: a checker that flags everything is not a checker. Both routes, so neither can
    # rot into an always-flag without a red -- the bound, and the delimiter head shipped today. The
    # letter-headed spelling is kept beside it because this guard PASSED it, correctly: it was
    # contained and linear, and it was still losing credentials. Containment is not correctness, and a
    # control that only ever shows this checker agreeing with the shipped pattern hides that.
    assert not _unbounded_scan_repeats(r"(?i)\b([a-z][a-z0-9+.\-]{0,63}://[^\s:/@]+):[^\s/@]+@")
    assert not _unbounded_scan_repeats(_LETTER_HEAD_DSN)
    assert not _unbounded_scan_repeats(
        r"(?i)(?<![a-z0-9+.\-])([a-z0-9+.\-]+://[^\s:/@]+):[^\s/@]+@"
    )

    checked: list[str] = []
    excused: set[str] = set()
    for module, applier in CREDENTIAL_SURFACES:
        applied = _applied_pattern_names(module, applier)
        # Positive control on the derivation, per surface: a silently-empty set passes vacuously.
        assert len(applied) >= 5, (
            f"{module.__name__}.{applier}: AST derivation found only {sorted(applied)} -- the "
            "instrument is broken, not the patterns"
        )
        for name in sorted(applied):
            offenders = _unbounded_scan_repeats(getattr(module, name).pattern)
            if name in SCAN_UNBOUNDED_BY_DESIGN:
                if offenders:
                    excused.add(name)
                continue
            assert not offenders, (
                f"{module.__name__}.{name} leaves {offenders} enterable in its scan prefix, which is "
                "quadratic in line length on log text an attacker can influence. Head it with a "
                "(?<![C]) covering the repetition's own class (lossless, and what _DSN_PASSWORD "
                "does), or bound the repetition (lossy -- read _repeat_cannot_restart first), or add "
                "the name to SCAN_UNBOUNDED_BY_DESIGN with the reason it cannot be re-entered."
            )
            checked.append(f"{module.__name__}.{name}")
    assert len(checked) >= 10, f"only {checked} were checked -- both surfaces should be covered"

    # The exemption table is exact AND non-stale, the two-sided shape this file uses everywhere: an
    # entry excusing a pattern the checker no longer flags tells a reader about a hazard that is gone.
    assert set(SCAN_UNBOUNDED_BY_DESIGN) == {"_LONG_B64"}
    assert excused == set(SCAN_UNBOUNDED_BY_DESIGN), (
        f"SCAN_UNBOUNDED_BY_DESIGN excuses {sorted(set(SCAN_UNBOUNDED_BY_DESIGN) - excused)}, which "
        "the checker does not flag. Remove the entry rather than leaving a false record."
    )


def test_the_label_prefix_bound_still_reaches_the_labels_it_was_added_for() -> None:
    """A bound low enough to be safe and too low to be useful passes the structural guard above while
    silently reverting the widening it was added for.

    This is the half of the old narrow guard the structural widening does NOT subsume, kept and
    extended to both copies of the vocabulary."""
    for module in (redact_mod, scrub_mod):
        assert re.fullmatch(r"\(\?:\[A-Za-z0-9\]\+\[\._-\]\)\{0,\d+\}", module._LABEL_PREFIX), (
            f"{module.__name__}._LABEL_PREFIX is {module._LABEL_PREFIX!r} -- it must carry an explicit "
            "{0,N} bound. With '*' or '+' the credential patterns become quadratic in line length "
            "(827 ms on one 6 KB hyphen run, against 1.5 ms before the widening)."
        )
    for label in ("ad_bind_password", "tls_key_password", "client_secret", "bearer_token"):
        assert REDACTION_PLACEHOLDER in redact_log_line(f"{label}=pw-B0und_Chk-99")
        assert CREDENTIAL_PLACEHOLDER in scrub_credentials(f"{label}=pw-B0und_Chk-99")


#: Text that must still reach the password behind it, standing where a DSN scheme stands. The long
#: entries are the point and they are NOT all schemes: ``\b`` anchors at the head of the whole unbroken
#: run the scheme sits in, so what has to survive is a long run of the scheme CLASS, wherever it came
#: from.
#:
#: THE FIRST SIX ARE REAL SCHEMES. The next two are long but BROKEN by "." and "-", which end a word
#: and so offered ``\b`` a later start position -- they survived the ``{0,63}`` bound, and the bound's
#: own note cited them as evidence that it only cost label text. The NEXT TWO are the shapes that note
#: did not cover: unbroken runs of the class, which took the whole match away and published the
#: password. Measured leaking on both surfaces while the bound stood.
#:
#: THE LAST SIX ARE A SECOND NARROWING THIS TABLE COULD NOT EXPRESS, and the gap is worth naming
#: because the table looked complete. Every entry above begins with a LETTER, and each one is
#: interpolated after "store dsn ", so the character in front of the run is always a space. The head
#: that shipped for #1547 refused a start unless the run's FIRST character was a letter, so a leading
#: run opening on a digit, "+", "." or "-" lost the match entirely -- and no row here could put one
#: there. These six do. They are not schemes and are not pretending to be: a request id, a date stamp,
#: a hex correlation id and three bare punctuation heads are what actually sits glued in front of a DSN
#: in log text. Measured leaking on both surfaces under the letter head.
_DSN_SCHEMES_THAT_MUST_REDACT = (
    "postgres",
    "postgresql+asyncpg",
    "mssql+pyodbc",
    "mongodb+srv",
    "sqlserver",
    "POSTGRES",
    "seg." * 40 + "postgres",
    "seg-" * 40 + "postgres",
    "x" * 200,
    "worker" + "0" * 64 + "postgres",
    "9-postgres",
    "2024-01-01-postgres",
    "8f3a-postgres",
    ".postgres",
    "-postgres",
    "+postgres",
)


def test_the_dsn_scan_still_reaches_every_scheme_shape_that_matters() -> None:
    """The scan's containment must not narrow what the scrubber catches, and once it did.

    THE TWO UNBROKEN ENTRIES ARE A REGRESSION TEST WITH A MEASURED FAILURE BEHIND THEM. While
    ``_DSN_PASSWORD`` carried a ``{0,63}`` bound on its scheme repetition, both leaked their password
    on BOTH surfaces: ``\\b`` anchors at the head of the unbroken run, not at the scheme, so 64
    characters of ``[A-Za-z0-9+.\\-]`` in front of a DSN took the whole match away rather than trimming
    a label. Measured at the 65th character.

    ASSERT THE VALUE IS ABSENT, not merely that a placeholder appeared: a clipped match could leave
    the password on the line beside a placeholder bought by another pattern."""
    secret = "pw-D5n_Pass-55"
    for scheme in _DSN_SCHEMES_THAT_MUST_REDACT:
        line = f"store dsn {scheme}://svc:{secret}@db.invalid:5432/mefor"
        for label, out in (
            ("support.redact", redact_log_line(line)),
            ("secretscrub", scrub_credentials(line)),
        ):
            assert secret not in out, (
                f"{label}: {scheme[:20]}... leaked the password -- got {out!r}"
            )

    # THE SHAPE ANOTHER FILE'S FIXTURE ALREADY HAD, restated here where the pattern lives. This is
    # tests/test_log_write_guard.py's straddling diagnostic: a long run of one letter written straight
    # onto a real scheme, which is what a truncating log line produces. It is the input that caught
    # the bound, and it belongs in this file so the next change to this pattern reds HERE first.
    straddling = f"{'q' * 973}postgres://mefor_svc:{secret}@dbhost:5432/mefor"
    assert secret not in redact_log_line(straddling)
    assert secret not in scrub_credentials(straddling)

    # AND THE WIDENING THE DELIMITER HEAD BROUGHT WITH IT, pinned so it cannot be given back silently.
    # "_" is a word character, so ``\b`` could not place a match after one and this line never redacted
    # under the pre-#1547 spelling; the lookbehind's class does not hold "_", so it does now.
    after_underscore = f"store dsn _postgres://svc:{secret}@db.invalid/mefor"
    assert secret not in redact_log_line(after_underscore)
    assert secret not in scrub_credentials(after_underscore)


#: Text that can sit glued in front of a DSN in a real log line, paired against the scheme table above
#: to build the differential corpus. The empty entry is the control, and the claim has to be made about
#: the PAIR rather than the head alone: a LETTER-headed scheme behind it is a shape every spelling of
#: this pattern has always matched, because the fixture's own "store dsn " puts a space in front. It is
#: not true of the empty head by itself -- an empty head in front of ".postgres" is exactly a case the
#: letter head lost. A literal " " row was tried and removed: the fixture already supplies that space,
#: so it produced a verdict identical to the empty entry on all 16 schemes rather than a second case.
_DSN_LEADING_RUNS = (
    "",
    "_",
    "9-",
    "2024-01-01-",
    "8f3a-",
    ".",
    "-",
    "+",
    "x" * 200,
    "seg." * 40,
)


def _sub_dsn(pattern: re.Pattern[str], line: str) -> str:
    """``line`` with ``pattern``'s password span replaced, keeping group 1 the way both modules do."""
    return pattern.sub(lambda m: f"{m.group(1)}:<pw>@", line)


def test_both_copies_of_the_dsn_pattern_are_the_same_source() -> None:
    """The two surfaces carry this regex by hand, and a one-sided edit must red HERE.

    ``secretscrub`` scrubs at WRITE time and ``support/redact`` at READ time, and both keep their own
    literal copy of ``_DSN_PASSWORD``. That duplication is deliberate -- the modules are neutral leaves
    and neither imports the other's patterns -- but it has now been edited by hand twice under BACKLOG
    #1547, and a narrowing shipped in BOTH copies both times.

    NOTHING ELSE IN THIS FILE CATCHES A ONE-SIDED FIX DIRECTLY. The differential arm runs over both
    modules, so it would red -- but only for corpus rows the earlier head happens to reach, and only
    while that corpus keeps its shape. An equality on the source is one line, cannot go vacuous, and
    names the real invariant: these are one pattern stored twice, not two patterns that happen to
    agree."""
    assert redact_mod._DSN_PASSWORD.pattern == scrub_mod._DSN_PASSWORD.pattern, (
        "the read-time and write-time copies of _DSN_PASSWORD have diverged:\n"
        f"  support/redact: {redact_mod._DSN_PASSWORD.pattern!r}\n"
        f"  secretscrub   : {scrub_mod._DSN_PASSWORD.pattern!r}\n"
        "A fix applied to one surface leaves the other leaking. Apply it to both, or state in both "
        "files why they must differ and widen this guard."
    )
    assert redact_mod._DSN_PASSWORD.flags == scrub_mod._DSN_PASSWORD.flags, (
        "the two copies compile with different flags, so the same source does not mean the same match."
    )


#: The leading runs the letter head could not reach AT ALL, which is the #1547 narrowing stated as
#: data. Paired with each earlier spelling below so the corpus control can assert BOTH dimensions: a
#: scheme set alone is blind to the head axis, and the head axis is where this defect lived.
_LETTER_HEAD_BLIND_RUNS = frozenset({"9-", "2024-01-01-", "8f3a-", ".", "-", "+"})


@pytest.mark.parametrize(
    ("earlier", "blind_runs"),
    ((_SHIPPED_BEFORE_DSN, frozenset()), (_LETTER_HEAD_DSN, _LETTER_HEAD_BLIND_RUNS)),
    ids=("pre-1547-word-boundary-head", "first-1547-letter-head"),
)
def test_the_dsn_head_redacts_everything_both_earlier_heads_did(
    earlier: str, blind_runs: frozenset[str]
) -> None:
    """No spelling of this head may redact a password the shipped one leaves on the line.

    THIS IS THE ARM THAT WOULD HAVE CAUGHT #1547's SECOND NARROWING, and it is written as a
    DIFFERENTIAL rather than as more table rows because the table could not state the property. Every
    entry in ``_DSN_SCHEMES_THAT_MUST_REDACT`` begins with a letter and each is interpolated after a
    space, so the head that shipped for #1547 -- which refused a start unless the run's first character
    was a letter -- passed that table while losing every DSN behind a digit-, "+"-, "."- or
    "-"-headed run. A table of shapes somebody thought of cannot fail for a shape nobody thought of.
    Comparing against the spellings this one replaced can, because a narrowing is defined relative to
    them.

    BOTH EARLIER HEADS, NOT JUST THE MOST RECENT. Each lost something the other kept -- ``\\b`` could
    not start after an underscore, the letter head could not start on a non-letter run -- so a
    comparison against either one alone has a blind spot exactly where that one was already blind.

    AND THE OUTPUT MUST MATCH, not merely the match/no-match verdict. A head that starts EARLIER
    captures more into group 1, and group 1 is kept verbatim, so a wider head that redacted the same
    password could still have rewritten the visible line. It does not, AT ONE MATCH SITE: the extra
    leading run sat in front of the old match and sits inside group 1 now, and both emit the same
    characters. THE EQUALITY IS SCOPED TO A ONE-DSN LINE ON PURPOSE, and the precondition is asserted
    rather than assumed. On a line carrying TWO DSNs the earlier head can miss one of them outright --
    ``store _postgres://a:S1@h and 9-mysql://c:S2@h`` is redacted once by the ``\\b`` head and twice by
    the shipped one -- so the outputs differ BECAUSE the shipped head is wider, which is the opposite
    of what this assertion's message would say. A future editor adding a realistic two-DSN row must
    widen the arm rather than read its red as a narrowing."""
    earlier_pattern = re.compile(earlier)
    secret = "pw-D5n_Pass-55"
    schemes_seen: set[str] = set()
    heads_seen: set[str] = set()
    for module in (redact_mod, scrub_mod):
        shipped = module._DSN_PASSWORD
        for head in _DSN_LEADING_RUNS:
            for scheme in _DSN_SCHEMES_THAT_MUST_REDACT:
                line = f"store dsn {head}{scheme}://svc:{secret}@db.invalid:5432/mefor"
                if not earlier_pattern.search(line):
                    continue
                schemes_seen.add(scheme)
                heads_seen.add(head)
                assert shipped.search(line), (
                    f"{module.__name__}: {earlier_pattern.pattern!r} redacts {head[:16]!r}+"
                    f"{scheme[:16]}... and the shipped head does not. That is a credential the "
                    "previous spelling caught, lost to this one."
                )
                assert line.count("://") == 1, (
                    "the output equality below compares whole lines and holds at ONE match site. "
                    f"{head[:16]!r}+{scheme[:16]}... carries more than one DSN -- see this test's "
                    "docstring before widening the corpus."
                )
                assert _sub_dsn(earlier_pattern, line) == _sub_dsn(shipped, line), (
                    f"{module.__name__}: the shipped head rewrites {head[:16]!r}+{scheme[:16]}... "
                    "differently from the spelling it replaced. Widening the head must not change "
                    "what an operator reads back."
                )

    # POSITIVE CONTROL ON THE CORPUS, OVER BOTH OF ITS DIMENSIONS. A differential over lines the
    # earlier pattern never matched is vacuously green, and the `continue` above is how that happens
    # silently. Two weaker spellings were tried and rejected, both measured. A floor on the NUMBER of
    # comparisons tolerates losing most of the corpus. A SCHEME set alone is worse than it looks: the
    # single leading run "x" * 200 reaches all 16 schemes under both earlier heads, so the corpus can
    # be pruned down to that one row -- deleting every non-letter run, which is the axis this defect
    # lived on -- and a scheme-only control still passes both arms. So assert the head axis too.
    assert schemes_seen == set(_DSN_SCHEMES_THAT_MUST_REDACT), (
        f"{sorted(s[:20] for s in set(_DSN_SCHEMES_THAT_MUST_REDACT) - schemes_seen)} never reached "
        f"the comparison -- no leading run puts them within reach of {earlier_pattern.pattern!r}, so "
        "this arm cannot fail for them. Add a run that does, rather than relaxing this."
    )

    # THE HEAD AXIS IS ASSERTED AS AN EXACT SET, INCLUDING THE BLIND SPOT, because "which runs this
    # spelling cannot reach" IS the #1547 narrowing and an inequality would hide it drifting. The
    # ``\b`` head reaches all 11; the letter head reaches 5 and is blind to the 6 in
    # ``_LETTER_HEAD_BLIND_RUNS``. If that blind set shrinks, the letter head was not what this file
    # says it was; if it grows, a run was added that no arm exercises.
    assert heads_seen == set(_DSN_LEADING_RUNS) - blind_runs, (
        f"{earlier_pattern.pattern!r} reached the leading runs "
        f"{sorted(h[:14] for h in heads_seen)}, not the expected "
        f"{sorted(h[:14] for h in set(_DSN_LEADING_RUNS) - blind_runs)}. Either the corpus lost a run "
        "or this spelling does not have the reach this file records for it."
    )


#: The length span the growth arm measures across, in characters. 8x rather than one doubling: linear
#: predicts 8 and the pattern this replaced measured 65 to 81, so the wider span separates the two by
#: more than the clock's noise can close, and both endpoints sit far above the timer's resolution.
_GROWTH_LENGTHS = (2048, 16384)

#: The growth allowed across that span. Measured on this interpreter: the delimiter-headed pattern
#: shipped today 6.9x to 8.1x, the ``\b``-headed one it replaced 62.0x to 63.6x. 24 sits 3x above the
#: slowest linear reading and 2.6x below the fastest quadratic one, so a loaded runner has to distort
#: one endpoint more than twofold before this flakes, and a reverted head cannot hide underneath it.
_MAX_GROWTH = 24.0

# A SHARE OF WALL-CLOCK COST STOOD HERE, AND IT IS DELETED RATHER THAN RETUNED. ``_MIN_DSN_COST_SHARE``
# required ``_DSN_PASSWORD.sub`` to be at least 0.5 of ``scrub_credentials``'s cost on the marked run,
# with the input held constant. It went red on ``test (windows-2025, py3.14)`` at a share of 0.467 --
# 0.591 ms of 1.266 ms, one failure in 15201 -- and the decomposition condemns it more thoroughly than
# the miss does. The share is D / (F + D), F being what the call spends outside the pass. On the box
# this file was written on: D 0.170 ms, F 0.033 ms, share 0.84, across 15 trials spanning 0.817 to
# 0.874. On that runner: D 0.591 ms, F 0.675 ms. D scaled 3.5x and F scaled 20x, so F/D moved from
# 0.19 to 1.14 -- a 6x swing in the composition, against the roughly 1.66x of headroom a quantity
# capped at 1.0 can offer at all. The tight local spread was read as though it said something about
# another box, and it does not.
#
# F IS MEASURED HERE RATHER THAN INFERRED: on that same box the 16 KB casefold costs 0.0033 ms, and
# the seven ``_admits`` calls one ``scrub_credentials`` makes (one at the entry gate, six inside
# ``_run``) cost 0.0295 ms. That is F to three decimal places. On this fixture those seven calls walk
# the folded line 22 times, not once per hint word: ``_admits`` short-circuits, and the entry gate
# hits on its first word. So the denominator is a substring-sweep cost and the numerator a scan -- two
# different primitives, timed separately and divided. WHY they scale apart on a shared runner is not
# established here, and a guess does not belong in a test; THAT they do is the whole finding, since
# the ratio is then a reading about the box as much as about the code.
#
# THE GENERAL SHAPE IS WORTH NAMING, BECAUSE THIS FILE SHIPPED IT TWICE. The deleted arm itself
# replaced a cross-input ratio (marked run over unmarked, 4x), on the correct finding that varying the
# input varies the gate work, so the denominator was not the thing the claim named. Holding the input
# constant fixed that one substitution and kept the shape: A COST SHARE IS A FRAGILE WITNESS WHATEVER
# YOU HOLD CONSTANT, because the denominator still moves for reasons that have nothing to do with the
# subject. Lowering the floor would be the same defect in a third costume, a threshold sized from one
# hosted observation. THIS FILE ALREADY KNEW, twice: both the mitigation guard and the scan-prefix
# guard are structural "for the reason the narrow version already gave: a timing assertion on a shared
# runner flakes". That reason was never carried across to this arm.
#
# THIS IS NOT A RULE AGAINST STOPWATCHES, AND THE GROWTH ARM ABOVE IS THE CONTRAST THAT SHOWS WHY. It
# is also a ratio of two timings, and it is sound for a reason the share could never have: it divides
# THE SAME WORK AT TWO INPUT LENGTHS, so a box that runs everything k times slower multiplies both
# endpoints by k and k cancels. That holds for the composite subjects too, where each endpoint mixes a
# scan with the sweeps: while both components stay linear in length, their relative weight drops out
# of the quotient, so even a component inflated 20x shifts the LEVEL and not the ratio. A slope change
# would move it, and that is the regression the arm is for.
#
# THE RED RUN IS ITSELF THE EVIDENCE FOR THAT, which is why it is worth keeping. On the runner where F
# came back 20x inflated, all five growth subjects passed and only the share failed. The share divided
# a regex scan by a substring sweep -- two different primitives at ONE length -- so nothing cancelled
# and the quotient was never only about the code. Measured over 12 runs here, the growth arm's margins
# run 2.05x to 3.32x against its threshold, where the share had 1.66x in total. ASK OF ANY TIMING
# RATIO WHAT CANCELS OUT OF IT. A tight spread on the box you measured it on answers a narrower
# question, and answers it for that box only.
#
# WHAT THE SHARE WAS REACHING FOR IS ALREADY CARRIED ABOVE, which is why removing it costs at least no
# coverage of #1547. The property #1547 is about is this pattern's own linearity, and the growth loop
# measures that on the BARE ``.sub`` in two subjects, armed by a positive control on the same bare
# call. The surface subjects assert that nothing inside ``scrub_credentials`` or ``redact_log_line`` is
# quadratic, and that stands without attributing the cost to any one pass. What is genuinely gone is a
# bound on the NON-DSN cost inside the ``scrub_credentials`` subject; no assertion here consumed it.
#
# WHAT REPLACES IT IS A COUNT. "Did this pass run, and how often" was always a fact about the code, and
# the recorder below reads it directly.


#: Every ``re.Pattern`` method that APPLIES the pattern to text, whether or not it scans -- ``match``
#: and ``fullmatch`` anchor at a position and are in the set anyway, because over-reporting an
#: application is the safe direction and under-reporting one is the failure this set exists to stop. A
#: recorder watching ``.sub`` alone would miss a future ``_run`` reaching for ``.subn`` or a
#: ``.finditer`` loop: the same walk, the same cost, and an arm below that stays green while a second
#: pass runs on every line. The membership is checked against ``re.Pattern`` itself in that arm, since
#: a typo in one of these strings would narrow the reading with nothing to report it.
_PATTERN_APPLICATIONS = frozenset(
    {"findall", "finditer", "fullmatch", "match", "scanner", "search", "split", "sub", "subn"}
)


class _RecordingPattern:
    """A compiled pattern that counts applications of itself and is otherwise the real object.

    NOT a ``re.Pattern`` subclass, because the type refuses subclassing, so ``isinstance(x,
    re.Pattern)`` is False for the length of a swap. Nothing on the ``scrub_credentials`` path
    type-checks a pattern today and the swap is undone before anything else looks, but a future
    ``_run`` spelled ``re.sub(_DSN_PASSWORD, ...)`` rather than ``_DSN_PASSWORD.sub(...)`` would red
    here with a TypeError from inside ``re``, naming this fixture for a change that is fine.
    """

    def __init__(self, name: str, pattern: re.Pattern[str], seen: Counter[str]) -> None:
        self._name = name
        self._pattern = pattern
        self._seen = seen

    def __getattr__(self, attr: str) -> Any:
        # An instance whose __dict__ is empty -- one built by copy, pickle, or a pytest assertion
        # repr, none of which run __init__ -- would otherwise ask itself for _pattern forever. Raise
        # AttributeError rather than let the lookup fail some other way: it is what `hasattr`
        # swallows, and `copy.copy` probes `hasattr(y, "__setstate__")` on exactly such an instance.
        if "_pattern" not in self.__dict__:
            raise AttributeError(attr)
        target = getattr(self._pattern, attr)
        if attr not in _PATTERN_APPLICATIONS:
            return target
        name, seen = self._name, self._seen

        def recorded(*args: Any, **kwargs: Any) -> Any:
            # Forward verbatim: a bounded `count=` or `pos=` on a future call site must reach the real
            # method, or this fixture reds with a TypeError naming itself instead of the property.
            seen[name] += 1
            return target(*args, **kwargs)

        return recorded


def _patterns_applied_during(
    module: ModuleType, names: set[str], call: Callable[[], object]
) -> Counter[str]:
    """How many times each of ``names`` was applied to text during ``call()``.

    Each is swapped for a recorder that delegates everything else to the real object, so this reads
    what RAN rather than what could have run. ``secretscrub._run`` is straight-line over module
    globals precisely so a swap here reaches the object it reads -- its own docstring says so, and a
    dispatch table would hold the pre-swap pattern by value and record nothing.

    Derive ``names`` BEFORE calling this. The derivation selects on ``isinstance(value, re.Pattern)``
    over the live namespace and a recorder is not one, so a set read during the swap comes back empty
    rather than wrong.

    The swap is module-global, which is why it is undone immediately. A log record scrubbed from
    another thread inside the window lands in this count if it opens a gate, and the caller reads that
    as one pattern applied twice; a record opening no gate applies nothing and leaves the reading
    alone. The window is one call wide and pytest drives it from one thread, so this is a caveat on
    the diagnosis rather than a live hazard.
    """
    seen: Counter[str] = Counter()
    originals = {name: getattr(module, name) for name in names}
    try:
        for name, pattern in originals.items():
            setattr(module, name, _RecordingPattern(name, pattern, seen))
        call()
    finally:
        for name, pattern in originals.items():
            setattr(module, name, pattern)
    return seen


def _adversarial_run(length: int, *, marker: bool) -> str:
    """A hyphen-and-dot run of ``length`` characters naming no credential word.

    "." and "-" both END a word, so the run offers the regex O(N) word-boundary start positions -- the
    shape an unbounded scheme class re-walks from every one of them. With ``marker`` the run ends in
    the "://" a DSN needs and never in the "@" a DSN also needs, so the scan runs to the end of the
    line and matches nothing, which is the worst case rather than a lucky one."""
    body = ("a-b." * (length // 4 + 1))[:length]
    return f"upstream error {body}{'://' if marker else '-nn-'}host"


def _fastest(call: Callable[[str], object], text: str, rounds: int) -> float:
    """The MINIMUM wall-clock time over ``rounds`` passes.

    A minimum is the one statistic the load of a shared runner cannot inflate; a mean or a max reports
    the box rather than the pattern."""
    best = math.inf
    for _ in range(rounds):
        start = time.perf_counter()
        call(text)
        best = min(best, time.perf_counter() - start)
    return best


def _growth(call: Callable[[str], object], *, rounds: int = 5, marker: bool = True) -> float:
    """Time at the long length over time at the short one, both on the adversarial run."""
    small = _fastest(call, _adversarial_run(_GROWTH_LENGTHS[0], marker=marker), rounds)
    large = _fastest(call, _adversarial_run(_GROWTH_LENGTHS[1], marker=marker), rounds)
    return large / small


def test_the_dsn_scan_grows_linearly_in_line_length() -> None:
    """Containment is bought for a GROWTH property, and only a stopwatch can see that one.

    The structural guard above proves containment is written down. It cannot prove the containment is
    the one that matters, and a bound or an anchor in the wrong place would pass it while the scan
    stayed quadratic. This arm measures what an unauthenticated sender would actually pay for: at
    16 KB the shipped-before pattern cost 302 ms against 0.17 ms for the delimiter-headed one, and
    every extra doubling widened that gap fourfold, so one long delimiter-free run would have hung a
    worker on first deployment.

    THE POSITIVE CONTROL IS THE SHIPPED-BEFORE PATTERN, MEASURED IN THIS RUN ON THIS BOX, and it is
    the whole reason this test can fail. A timing assertion with no control passes on a fast machine
    whatever the patterns do -- which is the "green a different pattern bought" failure of this file's
    own docstring, one layer down and wearing a stopwatch.

    THE OTHER WAY THIS COULD GO VACUOUSLY GREEN is an input that never reaches the pattern: that is
    linear for a reason which has nothing to do with the fix. Two arms below close it, and NEITHER
    CARRIES A STOPWATCH, because "did the pass run" is a fact about the code that a clock can only
    infer. One reads which admission gates the marked run opens, and that the unmarked run opens none.
    The other counts which patterns one ``scrub_credentials`` call actually applies. A share of
    wall-clock cost stood beside them until it went red on a hosted runner; the comment above
    ``_PATTERN_APPLICATIONS`` is the record of that, and is the one place this file argues it.

    NEITHER ARM IS RUN AGAINST ``redact_log_line``, and that is a property of the surface rather than
    an omission. Its copy is ungated and scans every line either way, so no input distinguishes
    "reached the pattern" from "did not" there -- measured before #1547 at 429 ms with the marker
    against 516 ms without it, at 16 KB. Its linearity is covered by the growth subjects above.
    """
    before = re.compile(_SHIPPED_BEFORE_DSN)
    before_growth = _growth(lambda text: before.sub("x", text), rounds=2)
    assert before_growth > _MAX_GROWTH, (
        f"the shipped-before pattern grew only {before_growth:.1f}x across {_GROWTH_LENGTHS}, which "
        f"is under the {_MAX_GROWTH}x threshold. This box or this input is not exercising the scan, so "
        "the assertions below cannot fail and prove nothing -- fix the fixture, do not raise the bar."
    )

    # THE GATE-REJECT PATH IS A SUBJECT IN ITS OWN RIGHT, and it is the one that runs on nearly every
    # record: a line naming no credential word at all. It reaches `_ANY_HINT`'s 15 substring sweeps and
    # then returns, so nothing below it is exercised -- which is exactly why it needs its own timed row
    # rather than being inferred from the marked one. Without it a regression that made that sweep
    # pathological would have no timed coverage anywhere in this file.
    subjects: tuple[tuple[str, Callable[[str], object], bool], ...] = (
        (
            "support.redact._DSN_PASSWORD",
            lambda text: redact_mod._DSN_PASSWORD.sub("x", text),
            True,
        ),
        ("secretscrub._DSN_PASSWORD", lambda text: scrub_mod._DSN_PASSWORD.sub("x", text), True),
        ("secretscrub.scrub_credentials", scrub_credentials, True),
        ("support.redact.redact_log_line", redact_log_line, True),
        ("secretscrub.scrub_credentials (gate-reject path)", scrub_credentials, False),
    )
    for label, call, marker in subjects:
        ratio = _growth(call, marker=marker)
        assert ratio <= _MAX_GROWTH, (
            f"{label} grew {ratio:.1f}x for 8x the line length, over the {_MAX_GROWTH}x threshold. "
            f"Linear is {_GROWTH_LENGTHS[1] // _GROWTH_LENGTHS[0]}x and the pattern this replaced "
            f"measured {before_growth:.0f}x in this same run. A repetition in a scan prefix has lost "
            "its containment, or a new pattern brought a fresh one."
        )

    # THE GROWTH READINGS ARE ONLY EVIDENCE ABOUT THIS PASS IF THIS PASS IS WHAT RAN, and that splits
    # into two questions a single cross-input ratio used to answer as one. The first is which gates the
    # marked run opens, below. The second is which patterns then actually run, further down. Both are
    # structural; a third arm answered the second question with a stopwatch and is deleted, for the
    # reasons recorded once above _PATTERN_APPLICATIONS.
    longest = _GROWTH_LENGTHS[1]
    marked_run = _adversarial_run(longest, marker=True)
    folded = marked_run.casefold()
    gates = _applied_gate_names(scrub_mod, "_run")
    assert "_DSN_HINT" in gates and len(gates) >= 6, (
        f"the gate derivation found {sorted(gates)} in secretscrub._run, which does not look like the "
        "per-pass gates. A hardcoded list here would assert less than it reads as asserting."
    )
    opened = tuple(
        sorted(name for name in gates if scrub_mod._admits(folded, getattr(scrub_mod, name)))
    )
    assert opened == ("_DSN_HINT",), (
        f"the marked adversarial run opens {opened} on secretscrub, not the DSN gate alone, so a "
        "second pass runs on this input and the growth readings above are not about this pattern. "
        "THE LIKELY CAUSE IS THE FIXTURE, NOT THE GATES: _adversarial_run spells its "
        "own prose ('upstream error ... host') and a credential word that is a substring of it opens "
        "a second gate. Change the fixture's wording, and only then look at _run."
    )
    assert not scrub_mod._admits(
        _adversarial_run(longest, marker=False).casefold(), scrub_mod._ANY_HINT
    ), (
        "the unmarked run now names a credential word, so it no longer isolates the marker. The "
        "fixture has drifted -- fix the run, do not drop this assertion."
    )

    # THE SECOND QUESTION IS WHETHER THE PASS ACTUALLY RAN, AND IT IS A COUNT RATHER THAN A CLOCK. The
    # arm above reads which gates ADMIT; this one reads which patterns were APPLIED, and how often.
    # They are not the same reading, and the gap between them is the case the deleted share could only
    # ever report as an unattributed number: a pattern reached WITHOUT a gate admits nothing and still
    # walks every line. Asserting both, a disagreement names that case.
    #
    # DERIVED OVER THE WHOLE ENTRY PATH, NOT `_run` ALONE. `CREDENTIAL_SURFACES` pairs this module with
    # `_run` because that is where its patterns are APPLIED, which is the right domain for the
    # structural guard. This arm asks a different question -- what does one `scrub_credentials` CALL
    # touch -- so a pattern applied in the entry function above `_run` belongs to it too. Reading
    # `_run` alone would be this file's own failure 2, a domain narrower than the surface.
    #
    # THE ENTRY FUNCTION APPLIES NO PATTERN TODAY, so the union adds no name to the six and is a no-op
    # on this tree. It is here for the day that stops being true, which is the day reading `_run`
    # alone would start being wrong with nothing to report it. THE DERIVATION IS ONE LEVEL DEEP either
    # way -- it walks a function body for module-level names and does not follow calls -- so a pattern
    # applied inside a NEW helper that `_run` calls is outside this domain. That limit is shared with
    # the structural guard above, which derives the same way; widening it is one change for both.
    applied = _applied_pattern_names(scrub_mod, "_run") | _applied_pattern_names(
        scrub_mod, "scrub_credentials"
    )
    assert "_DSN_PASSWORD" in applied, (
        f"the pattern derivation found {sorted(applied)} across secretscrub.scrub_credentials and "
        "._run, and _DSN_PASSWORD is not among them. Either the pattern was renamed or it is no "
        "longer applied on this path; nothing below can be about it until that is resolved."
    )
    assert len(applied) >= 6, (
        f"the pattern derivation found only {sorted(applied)}, which does not look like the per-pass "
        "patterns. A hardcoded list here would assert less than it reads as asserting."
    )

    # POSITIVE CONTROL ON THE TWO INSTRUMENTS THIS ARM RUNS ON, because a zero from either is otherwise
    # indistinguishable from the code having stopped. First the method list: a typo in one of those
    # strings silently narrows what counts as an application, so tie it to the real type. `re.Pattern`
    # may grow a method, which is why this is a subset check and not equality.
    pattern_methods = {
        name
        for name in dir(re.Pattern)
        if not name.startswith("_") and callable(getattr(re.Pattern, name, None))
    }
    assert not _PATTERN_APPLICATIONS - pattern_methods, (
        f"{sorted(_PATTERN_APPLICATIONS - pattern_methods)} in _PATTERN_APPLICATIONS is not a "
        "re.Pattern method, so the recorder can never see it fire -- fix the spelling"
    )

    # Then the recorder, driven through the module global by a line that MUST match, so a broken swap
    # reds here rather than being read as "the pass stopped running" thirty lines down.
    control = _patterns_applied_during(
        scrub_mod,
        {"_DSN_PASSWORD"},
        lambda: scrub_mod._DSN_PASSWORD.sub("x", "postgres://user:pw@host"),
    )
    assert control == Counter({"_DSN_PASSWORD": 1}), (
        f"the recorder read {dict(control)} for one direct application of _DSN_PASSWORD through the "
        "module global. The swap or the counting is broken, so every reading below is about this "
        "fixture rather than about secretscrub."
    )

    ran = _patterns_applied_during(scrub_mod, applied, partial(scrub_credentials, marked_run))
    assert ran == Counter({"_DSN_PASSWORD": 1}), (
        f"one scrub_credentials call on the marked adversarial run applied {dict(ran)}, not "
        "_DSN_PASSWORD exactly once, so the growth readings above are not about this pattern alone. "
        "Read it this way. AN EMPTY reading means the pass stopped running at all. A COUNT ABOVE ONE "
        "means one pattern is now walked repeatedly per call. A SECOND NAME, while the gate arm above "
        f"still sees only {opened} open, means that pattern is reached with no gate in front of it -- "
        "a cost defect in _run or in scrub_credentials. A second name WITH a red on the gate arm is "
        "the fixture drifting instead; fix the run's wording, as that assertion says."
    )


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
