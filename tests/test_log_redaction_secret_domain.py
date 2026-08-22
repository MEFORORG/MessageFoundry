# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
        name="mefor_env_value",
        line="startup MEFOR_STORE_ENCRYPTION_KEY=kv-Str0ng_Key-11 loaded",
        secret="kv-Str0ng_Key-11",
        patterns=("_MEFOR_SECRET",),
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
)


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
#: ``transports/soap.py`` raises "ws_password_type must be 'text' or 'digest'" -- but BOTH of those real
#: strings quote the word, so ``\s+`` cannot match and they survive a wide pattern and a narrow one
#: alike. Using them as the guard would have looked like coverage and tested nothing. Run against the
#: widened ``(bearer|basic|digest)`` alternative, the first two lines below are eaten and the real
#: engine strings are not, which is why the fixture is written this way.
ORDINARY_DIAGNOSTICS = (
    "falling back to basic auth for this hop",
    "server offered digest challenge, retrying",
    "oauth2_auth_style must be 'basic' or 'post', got 'bogus'",
    "SOAP ws_password_type must be 'text' or 'digest' (ADR 0015)",
    "INFO engine started on port 8765",
    "connection IB_DEMO_ADT bound, password rotation scheduled",
)


@pytest.mark.parametrize("line", ORDINARY_DIAGNOSTICS)
def test_ordinary_engine_diagnostics_are_not_eaten_by_the_credential_patterns(line: str) -> None:
    """A diagnostic that carries no credential must survive intact."""
    assert redact_log_line(line) == line, (
        f"a credential pattern ate an ordinary diagnostic: {line!r} -> {redact_log_line(line)!r}"
    )


def test_redactor_is_the_backstop_for_both_named_surfaces() -> None:
    """The support archive and the log-tail route both go through this module, so a hole lands twice.

    Asserted by reading the two sources rather than by trusting the docstrings, so moving either call
    off the shared redactor reds this test instead of quietly halving the coverage."""
    pkg = pathlib.Path(redact_mod.__file__).resolve().parent.parent
    bundle = (pkg / "support" / "bundle.py").read_text(encoding="utf-8")
    api = (pkg / "api" / "app.py").read_text(encoding="utf-8")
    assert "from messagefoundry.support.redact import redact_log_text" in bundle
    assert "from messagefoundry.support.redact import redact_log_line" in api
