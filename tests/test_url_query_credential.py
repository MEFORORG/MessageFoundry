# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A credential in an outbound ``url``'s query string is a RECORDED loosening (ASVS 14.2.1).

The vault re-read of 2026-10-01 found it accepted with no line anywhere: ``refuse_url_credentials``
covers the userinfo and never the query. On a hop the no-escape credential rule does not refuse, it
is WARNED and reported; the reason is on ``transports.egress.warn_url_query_credentials``. Every
positive arm has a benign-parameter control, so a test is not green because the detector names every
parameter.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    ActiveWindow,
    ConnectorType,
    Destination,
    Priority,
    Schedule,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    FhirLookupSpec,
    Registry,
    WiringError,
    build_outbound_connection,
    load_config,
    query_credential_hops,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.secretscrub import credential_query_params
from messagefoundry.store import MessageStore
from messagefoundry.transports.egress import (
    check_egress_allowed,
    check_fhir_lookup_allowed,
    warn_url_query_credentials,
)

_MARK = "carries a credential in its query string"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://p.example.invalid/x?key=AAA&fmt=json", ["key"]),
        ("https://p.example.invalid/x?subscription-key=AAA", ["subscription-key"]),
        ("https://p.example.invalid/blob?sv=1&sig=AAA&se=2", ["sig"]),
        (
            "https://p.example.invalid/x?X-Amz-Signature=A&X-Amz-Credential=B",
            ["X-Amz-Credential", "X-Amz-Signature"],
        ),
        ("https://p.example.invalid/x?access_token=AAA", ["access_token"]),
        (
            "https://p.example.invalid/x?api_key=A&client_secret=B&password=C",
            ["api_key", "client_secret", "password"],
        ),
        # The example docs/SECURITY-LOOSENING.md gives of a name that only looks like a credential.
        ("https://p.example.invalid/x?csrf_token=AAA", ["csrf_token"]),
    ],
)
def test_detector_names_credential_parameters(url: str, expected: list[str]) -> None:
    assert credential_query_params(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        # Benign controls: substrings of a credential word that are not the word.
        "https://p.example.invalid/x?format=json&keyword=lab&monkey=1&bypass=2&passage=3",
        "https://p.example.invalid/x?code=404&state=RUNNING",  # OIDC words, ordinary here
        "https://p.example.invalid/x?page_token=AAA",  # a pagination cursor, exempt by name
        "https://p.example.invalid/x",
        "not a url at all",
    ],
)
def test_detector_leaves_benign_parameters_alone(url: str) -> None:
    assert credential_query_params(url) == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # camelCase tails, the common partner spellings the first cut missed.
        (
            "https://p.example.invalid/x?accessToken=a&clientSecret=b",
            ["accessToken", "clientSecret"],
        ),
        ("https://p.example.invalid/x?apiKey=a&authToken=b", ["apiKey", "authToken"]),
        # Acronym-prefixed Title-case segments (review round 2).
        ("https://p.example.invalid/x?SASToken=a&HMACSignature=b", ["HMACSignature", "SASToken"]),
        # Control: a lower-case run is not a camelCase boundary, and all-capitals is not split.
        ("https://p.example.invalid/x?turkey=a&MONKEY=b&hotkeys=c", []),
        # Control: pagination cursors, sort keys and public keys end in a credential word only.
        ("https://p.example.invalid/x?pageToken=a&next_page_token=b&sortKey=c&publicKey=d", []),
        # Lander QA: one-word compounds, bare auth and jwt, digits, brackets and a "+" separator.
        (
            "https://p.example.invalid/x?accesstoken=a&authkey=b&auth=c&jwt=d&sessionid=e",
            ["accesstoken", "auth", "authkey", "jwt", "sessionid"],
        ),
        (
            "https://p.example.invalid/x?key1=a&api_key2=b&apiKey2=c&token[]=d&api+key=e",
            ["'api key'", "'token[]'", "apiKey2", "api_key2", "key1"],
        ),
        # Control: ids and keys that are not secrets, and flags that end in auth or jwt.
        (
            "https://p.example.invalid/x?idempotency_key=a&partition_key=b&routingKey=c"
            "&NextPartitionKey=e&NextRowKey=f&requireAuth=1&useOAuth=1&useJwt=1",
            [],
        ),
        # Review round 3: an Azure account key, and an indexed array name.
        (
            "https://p.example.invalid/x?primaryKey=a&secondaryKey=b&token[0]=c",
            ["'token[0]'", "primaryKey", "secondaryKey"],
        ),
    ],
)
def test_detector_reads_camel_case_tails(url: str, expected: list[str]) -> None:
    assert credential_query_params(url) == expected


def test_detector_escapes_a_control_character_in_a_decoded_name() -> None:
    """``parse_qsl`` decodes ``%0A``; the name reaches a log line, so it must not carry a raw newline."""
    [name] = credential_query_params("https://p.example.invalid/x?x%0Afake_token=1")
    assert "\n" not in name and name.isprintable()
    assert "fake_token" in name  # still named, escaped rather than dropped


def test_a_decoded_name_cannot_forge_a_second_entry() -> None:
    """A printable name can still carry ``); `` that reads as the end of one ``check`` entry."""
    [name] = credential_query_params("https://p.example.invalid/x?a%29%3B%20OB_EVIL%20%28api_key=1")
    assert name.startswith("'") and name.endswith("'")  # quoted by repr, so it reads as one name


# --- the settings-view mask: coarse and fail-closed (Manager decision on PR 1912) ---------------
#
# CORRECTED 2026-10-01: the tests that stood here pinned a PRECISE mask, which kept the user, host
# and path and replaced only the password and credential query values, plus a mirror of urllib's
# proxy parser and a span scan. Three review rounds each found a reader that disagreed with it, so
# the Manager replaced it with the coarse rule below; those pins are gone with the code they pinned.


def _shown(url: object, key: str = "url") -> object:
    from messagefoundry.config.wiring import redacted_settings

    return redacted_settings({key: url})[key]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # userinfo, in every shape the precise mask chased
        ("http://user:1234/5@proxy.example.invalid", "http://<redacted>"),
        ("http://alice@corp:p?ss@proxy.example.invalid:3128", "http://<redacted>"),
        ("user:pw@proxy.example.invalid:3128", "<redacted>"),  # no scheme
        ("https://token@h.example.invalid/x", "https://<redacted>"),  # user-only token
        # percent-escaped "@" and ":", any case
        ("http://user:pw%40h.example.invalid/x", "http://<redacted>"),
        ("http://user%3Apw@h.example.invalid/x", "http://<redacted>"),
        ("http://user%3apw%40h.example.invalid/x", "http://<redacted>"),
        ("http://user%3ASYNTHETIC-4/x", "http://<redacted>"),  # %3A alone, no "@" anywhere
        # a credential-looking query name
        ("https://p.example.invalid/x?api_key=SYNTHETIC-1&fmt=json", "https://<redacted>"),
        ("https://p.example.invalid/x?accessToken=SYNTHETIC-2", "https://<redacted>"),
        # an "@" that is only an email: withheld too, by design
        ("https://h.example.invalid/x?email=a@b.example.invalid", "https://<redacted>"),
        # a value urlsplit refuses
        ("http://[::1/x", "http://<redacted>"),
        # a scheme-shaped prefix without "//" is not shown as a scheme
        ("mailto:ops@example.invalid", "<redacted>"),
    ],
)
def test_a_url_that_may_carry_a_credential_is_withheld_whole(url: str, expected: str) -> None:
    assert _shown(url) == expected
    assert _shown(url, "proxy_url") == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://plain.example.invalid/path?q=1&r=2",
        "http://proxy.example.invalid:3128",
        "https://h.example.invalid:8443/x?fmt=json&keyword=lab#frag",
        "https://[::1]:8443/x",
        # Review of 0c6b32e5c4: benign ";" and "#" name=value segments the segment leg reads.
        "https://h.example.invalid/app;version=2",
        "https://h.example.invalid/x#section=3",
    ],
)
def test_a_plain_url_with_no_credential_is_unchanged(url: str) -> None:
    """The control: a rule that withheld every URL would pass the test above."""
    assert _shown(url) == url
    assert _shown(url, "smart_token_url") == url


@pytest.mark.parametrize(
    "url",
    [
        "https://h.example.invalid/x?a=1;api_key=SYNTH-B",  # Rack splits a query on ";"
        "https://h.example.invalid/app;jsessionid=SYNTH-A?x=1",  # servlet path parameter
        "https://h.example.invalid/x?fmt=json#access_token=SYNTH-C",  # fragment
        "https://h.example.invalid/x?x=1?api_key=SYNTH-D",  # after a second "?"
        "jdbc:sqlserver://db.example.invalid:1433;user=u;password=SYNTH-PW",
        "https://h.example.invalid/x#api_\tkey=SYNTH-J",  # a tab inside a fragment name
        # Review of 0c6b32e5c4: a tab INSIDE a percent-escape, which urlsplit drops before decoding.
        "https://h.example.invalid/x#api%5\tFkey=SYNTH-K",
        "https://h.example.invalid/x?a=1;api%5\tFkey=SYNTH-L",
        "https://h.example.invalid/x?a=1?api%5\tFkey=SYNTH-M",
        # ... a "%40" or "%3A" broken by a tab, which urlsplit rejoins.
        "https://SYNTH-N%\t40h.example.invalid/x",
        "https://user%\t3ASYNTH-O%\t40h.example.invalid/x",
        # ... and a value with no separator before its first name=value.
        "token=SYNTH-P",
        "AccountKey=SYNTH-Q;AccountName=x",
    ],
)
def test_a_credential_name_outside_the_ampersand_query_is_withheld(url: str) -> None:
    """Review of a87fcb2932: the detector reads the query urlsplit finds, split on "&", so these
    were shown. The segment leg reads every segment after "?", "&", "#" and ";"."""
    shown = str(_shown(url))
    assert "SYNTH" not in shown and "<redacted>" in shown, shown


def test_a_bare_path_secret_is_shown_and_documented_as_such() -> None:
    """The rule's stated limit, pinned so a reader does not take it for full coverage: a secret
    that is a bare path segment has no name or delimiter to find."""
    url = "https://hooks.example.invalid/services/T000/B000/SYNTH-PATH"
    assert _shown(url) == url


def test_a_path_name_value_is_withheld_through_the_first_segment() -> None:
    """The first segment is read too (review of 0c6b32e5c4), so a path ``name=value`` whose name
    ends in a credential word is withheld even with no separator before it."""
    assert _shown("https://h.example.invalid/x/api_key=SYNTH-PATH2") == "https://<redacted>"


def test_every_url_setting_key_and_the_proxy_name_use_the_rule() -> None:
    """Review of a87fcb2932: only "url" and "proxy_url" held a credential in these tests, so a
    narrowed suffix rule would have passed. And a "proxy" key, which the suffix rule's comment
    claimed a name set covered, was not covered at all."""
    from messagefoundry.config.wiring import env, redacted_settings

    shown = redacted_settings(
        {
            "smart_token_url": "https://t.example.invalid/token?client_secret=SYNTH-E",
            "callback_uri": "https://u:SYNTH-F@c.example.invalid/cb",
            "fhir_endpoint": "https://f.example.invalid/r4?api_key=SYNTH-G",
            "proxy": "http://u:SYNTH-H@proxy.example.invalid:3128",
            "url": env("MEFOR_URL", default="https://t.example.invalid/x?a=1;token=SYNTH-I"),
            # Review of 0c6b32e5c4: a bare "uri" and an http_proxy-style name.
            "uri": "https://u:SYNTH-R@h.example.invalid/x",
            "http_proxy": "http://u:SYNTH-S@p.example.invalid:3128",
            # ... and the RAW connections.toml marker, undecoded.
            "callback_url": {"env": "MEFOR_CB", "default": "https://u:SYNTH-T@h.example.invalid/x"},
        }
    )
    assert "SYNTH" not in str(shown), shown
    assert shown["callback_url"] == {"env": "MEFOR_CB", "default": "https://<redacted>"}


def test_an_env_default_url_is_withheld_by_the_same_rule() -> None:
    from messagefoundry.config.wiring import env, redacted_settings

    shown = redacted_settings(
        {
            "url": env("MEFOR_URL", default="https://u:SYNTHETIC-3@p.example.invalid/x"),
            "proxy_url": env("MEFOR_PROXY", default="http://proxy.example.invalid:3128"),
        }
    )
    assert shown["url"] == {"env": "mefor_url", "default": "https://<redacted>"}
    assert shown["proxy_url"]["default"] == "http://proxy.example.invalid:3128"


def test_the_mask_is_linear_in_the_length_of_the_url() -> None:
    """The review of 870c1afcbf measured the span scan at about 4x per doubling on a run of "?".
    The coarse rule is a few scans; doubling the input must not much more than double the time."""
    import time
    import urllib.parse

    from messagefoundry.config.wiring import _mask_url

    def cost(n: int) -> float:
        url = "https://h.example.invalid/x" + "?" * n + ";" * n + "&a=1" * n
        best = float("inf")
        for _ in range(5):
            # urlsplit is lru-cached, so a repeat run would time only a cache hit (review of
            # a87fcb2932). Clear it, so every run pays for the parse.
            getattr(urllib.parse.urlsplit, "cache_clear", lambda: None)()
            began = time.perf_counter()
            _mask_url(url)
            best = min(best, time.perf_counter() - began)
        return best

    small, large = cost(20_000), cost(80_000)
    assert large < small * 12, (small, large)  # 4x the input; quadratic would be about 16x


def test_the_composed_mask_never_shows_a_value_any_reader_takes() -> None:
    """The 30,000-URL oracle, kept from the precise mask. Wherever a seeded generator puts the test
    value QZXJ among the characters that move each reader's spans, and inserts "%40" and "%3A" as
    whole tokens, QZXJ never appears in the view when any of these readers takes it: the warning
    detector, a ``;``-splitting query reader (Rack), a fragment reader, urllib's proxy parser and
    urlsplit's netloc. The ``;`` and fragment readers are NOT the rule's own legs, so the test can
    fail for a shape the rule does not call (review of a87fcb2932: the detector arm alone was
    circular)."""
    import random
    import urllib.parse
    import urllib.request

    from messagefoundry.secretscrub import _is_credential_param

    def independent_readers(url: str) -> list[list[tuple[str, str]]]:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return []
        return [
            urllib.parse.parse_qsl(parts.query, separator=";"),
            urllib.parse.parse_qsl(parts.fragment),
            urllib.parse.parse_qsl(parts.query.partition("?")[2]),  # after a second "?"
        ]

    rng = random.Random(14_2_1)
    named = by_other_reader = in_password = in_netloc = withheld = 0
    alphabets = ("h:/@?#&=1.", "h:/@?#&=1.\t\n", "h:/?#&=1.;")
    for _ in range(30000):
        alphabet = rng.choice(alphabets)
        tokens = [*alphabet, "%40", "%3A", "%3a"]
        head = "".join(rng.choice(tokens) for _ in range(rng.randint(0, 10)))
        tail = "".join(
            rng.choice([t for t in tokens if t != "="]) for _ in range(rng.randint(0, 10))
        )
        # The NAME varies too (review of 0c6b32e5c4), including a tab inside a percent-escape and
        # a benign name, so the readers below can disagree with the rule and some URLs pass.
        name = rng.choice(("key", "api_key", "api%5Fkey", "api%5\tFkey", "fmt"))
        url = f"http://{head}{rng.choice('?&;#')}{name}=QZXJ{tail}"
        shown = str(_shown(url, "proxy_url"))
        withheld += "<redacted>" in shown
        if credential_query_params(url):
            named += 1
            assert "QZXJ" not in shown, (url, shown)
        for pairs in independent_readers(url):
            if any("QZXJ" in val and _is_credential_param(name) for name, val in pairs):
                by_other_reader += 1
                assert "QZXJ" not in shown, (url, shown)
        try:
            password = urllib.request._parse_proxy(url)[2]  # type: ignore[attr-defined]
        except ValueError:
            password = None
        if password and "QZXJ" in password:
            in_password += 1
            assert "QZXJ" not in shown, (url, shown)
        try:
            netloc_password = urllib.parse.urlsplit(url).password
        except ValueError:
            netloc_password = None
        if netloc_password and "QZXJ" in netloc_password:
            in_netloc += 1
            assert "QZXJ" not in shown, (url, shown)
    # Liveness: each reader's arm is reached, and the generator does not withhold everything.
    assert named > 1000 and by_other_reader > 1000, (named, by_other_reader)
    assert in_password > 100 and in_netloc > 20, (in_password, in_netloc)
    # Some URLs carry only the benign name and nothing else that withholds, so not all are withheld.
    assert 15000 < withheld < 30000, withheld


def test_detector_drops_a_control_character_inside_a_name() -> None:
    """urlsplit drops tab, CR and LF before parse_qsl decodes a name, so the detector names
    api_key in both of these (kept from the precise mask's tests)."""
    assert credential_query_params("https://h.example.invalid/p?api_\tkey=S") == ["api_key"]
    assert credential_query_params("https://h.example.invalid/x?api%5\tFkey=S") == ["api_key"]


def test_detector_returns_names_never_values() -> None:
    names = credential_query_params("https://p.example.invalid/x?token=SYNTHETIC-SECRET-1")
    assert names == ["token"]
    assert not any("SYNTHETIC" in n for n in names)


# --- the construction WARNING ------------------------------------------------------------------


def _rest(url: str) -> Destination:
    return Destination(name="OB_REST", type=ConnectorType.REST, settings={"url": url})


def test_build_warns_naming_the_connection_and_parameter_never_the_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(
            _rest("https://p.example.invalid/x?key=SYNTHETIC-SECRET-2&fmt=json"),
            EgressSettings(deny_by_default=False),
        )
    [line] = [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]
    assert "'OB_REST'" in line and "(parameter(s) key)" in line
    assert "SYNTHETIC-SECRET-2" not in line and "p.example.invalid" not in line


def test_build_with_a_benign_query_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(
            _rest("https://p.example.invalid/x?fmt=json&keyword=lab"),
            EgressSettings(deny_by_default=False),
        )
    assert not [r for r in caplog.records if _MARK in r.getMessage()]


def test_build_is_not_refused_under_an_allowlist(caplog: pytest.LogCaptureFixture) -> None:
    """Warn, not refuse: the allow-listed branch, which does refuse userinfo, still lets it through."""
    egress = EgressSettings(allowed_http=["p.example.invalid"])
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(_rest("https://p.example.invalid/x?sig=SYNTHETIC"), egress)
    assert [r for r in caplog.records if _MARK in r.getMessage()]


# --- the single reader, `check` and the registry -----------------------------------------------


def _registry() -> Registry:
    reg = Registry()
    for name, url in (
        ("OB_KEYED", "https://p.example.invalid/x?key=SYNTHETIC-3"),
        ("OB_PLAIN", "https://p.example.invalid/x?fmt=json"),
    ):
        reg.add_outbound(
            build_outbound_connection(
                name, ConnectionSpec(type=ConnectorType.REST, settings={"url": url})
            )
        )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ENV",
            ConnectionSpec(type=ConnectorType.REST, settings={"url": EnvRef("MEFOR_ENV_URL")}),
        )
    )
    return reg


def test_reader_lists_only_the_credentialed_url_and_no_value() -> None:
    assert query_credential_hops(_registry()) == [("OB_KEYED", "key")]


def test_reader_and_build_cover_a_fhir_lookup(caplog: pytest.LogCaptureFixture) -> None:
    """A FhirLookup dials its ``url`` too, through its own egress check, so both surfaces reach it."""
    from messagefoundry.config.wiring import FhirLookupSpec
    from messagefoundry.transports.egress import check_fhir_lookup_allowed

    reg = _registry()
    url = "https://fhir.example.invalid/R4?api_key=SYNTHETIC-6"
    reg.add_fhir_lookup(FhirLookupSpec(name="LK", settings={"url": url}))
    assert ("fhir_lookup:LK", "api_key") in query_credential_hops(reg)
    with caplog.at_level(logging.WARNING):
        check_fhir_lookup_allowed("LK", {"url": url}, EgressSettings(deny_by_default=False))
    [line] = [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]
    assert "FhirLookup 'LK'" in line and "SYNTHETIC" not in line


_CONFIG = """
from messagefoundry import MLLP, Rest, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15098), router="r")
outbound("OB_KEYED", Rest(url="https://p.example.invalid/x?sig=SYNTHETIC-4"))
outbound("OB_PLAIN", Rest(url="https://p.example.invalid/x?fmt=json"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_KEYED", msg)
"""

_TOML = """
[store]
backend = "sqlite"

[ai]
environment = "dev"

[security]
block_unlisted_outbound = false
allow_unencrypted_phi = true
allow_unencrypted_phi_under_strict_enforcement = true
"""


def _write(tmp_path: Path, module: str) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(module, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    return cfg


def test_check_names_the_connection_and_parameter(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    report = run_checks(_write(tmp_path, _CONFIG), run_lint=False)
    r = next(x for x in report.results if x.name == "url-query-credential")
    assert r.ok and not r.required and not r.skipped
    assert "OB_KEYED (sig)" in r.detail
    assert "OB_PLAIN" not in r.detail and "SYNTHETIC" not in r.detail


def test_check_says_none_on_a_clean_graph(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    clean = _CONFIG.replace("?sig=SYNTHETIC-4", "?fmt=xml")
    report = run_checks(_write(tmp_path, clean), run_lint=False)
    r = next(x for x in report.results if x.name == "url-query-credential")
    assert "no outbound or FhirLookup url carries a credential-like query parameter" in r.detail


# --- once per reload (vault BACKLOG #2910) -----------------------------------------------------
#
# A reload runs ``build_check`` over the whole new graph, and that check warns. It then rebuilds the
# outbounds that changed and the FhirLookup executor, and each rebuild runs the egress check again.
# Only the WARNING is dropped on the rebuild: every refusal still runs there (vault BACKLOG #2605).

_KEYED = "https://p.example.invalid/x?key=PLACEHOLDER&v={v}"
_LOOKUP_URL = "https://fhir.example.invalid/R4?api_key=PLACEHOLDER"


_UNREAD = "its url did not resolve, so the URL query-credential check could not read it"


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records]


def _warned(caplog: pytest.LogCaptureFixture, label: str) -> int:
    return sum(1 for r in caplog.records if _MARK in r.getMessage() and label in r.getMessage())


def _reload_graph(
    *,
    v: int = 1,
    added: bool = False,
    fhir: bool = False,
    priority: Priority | None = None,
    url: str | EnvRef | None = None,
    schedule: Schedule | None = None,
) -> Registry:
    reg = Registry()
    for name in ["OB_KEYED", "OB_ADDED"] if added else ["OB_KEYED"]:
        settings = {"url": _KEYED.format(v=v) if url is None else url}
        spec = ConnectionSpec(type=ConnectorType.REST, settings=settings)
        reg.add_outbound(
            build_outbound_connection(name, spec, priority=priority, schedule=schedule)
        )
    if fhir:
        reg.add_fhir_lookup(FhirLookupSpec(name="LK", settings={"url": _LOOKUP_URL}))
    return reg


@pytest.fixture
async def reload_store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "query-credential-reload.db")
    yield s
    await s.close()


def _reload_runner(store: MessageStore, reg: Registry, **kw: Any) -> RegistryRunner:
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False), **kw
    )


async def test_a_reload_warns_once_for_a_changed_and_an_added_outbound(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """``OB_KEYED`` changes, so it takes the in-place rebuild; ``OB_ADDED`` is new, so it takes the
    added-lane build. Both used to log twice per reload: once in build_check, once in the rebuild."""
    runner = _reload_runner(reload_store, _reload_graph(v=1))
    try:
        await runner.start()
        before = runner._destinations["OB_KEYED"]
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.reload(_reload_graph(v=2, added=True))
        assert runner._destinations["OB_KEYED"] is not before  # the rebuild ran
        assert "OB_ADDED" in runner._destinations
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "outbound 'OB_ADDED'") == 1
    finally:
        await runner.stop()


async def test_a_reload_warns_once_for_an_unchanged_outbound(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: an unchanged lane is not rebuilt, so the one line is build_check's. It still
    fires on every reload, so the change did not drop the warning from a reload altogether."""
    runner = _reload_runner(reload_store, _reload_graph(v=1))
    try:
        await runner.start()
        before = runner._destinations["OB_KEYED"]
        for _ in range(2):
            caplog.clear()
            with caplog.at_level(logging.WARNING):
                await runner.reload(_reload_graph(v=1))
            assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert runner._destinations["OB_KEYED"] is before  # never rebuilt
    finally:
        await runner.stop()


async def test_a_reload_warns_once_for_a_fhir_lookup(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    runner = _reload_runner(reload_store, _reload_graph(fhir=True))
    try:
        await runner.start()
        before = runner._fhir_lookup_executor
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.reload(_reload_graph(fhir=True))
        assert runner._fhir_lookup_executor is not None
        assert runner._fhir_lookup_executor is not before  # rebuilt from the new graph
        assert _warned(caplog, "FhirLookup 'LK'") == 1
    finally:
        await runner.stop()


async def test_an_activation_reload_warns_once_for_a_lane_leaving_the_passive_park(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Another rebuild a reload makes: a passive standby's lane, built at its activation through
    ``_ensure_destination_built``. docs/SECURITY-LOOSENING.md is the source of record for where the
    warning fires."""
    runner = _reload_runner(
        reload_store, _reload_graph(priority=Priority.CRITICAL), dr_standby=Priority.CRITICAL
    )
    try:
        await runner.start()
        assert "OB_KEYED" not in runner._destinations  # parked unbuilt on the passive box
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.reload()
        assert "OB_KEYED" in runner._destinations
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
    finally:
        await runner.stop()


def test_the_rebuild_form_still_refuses_and_only_drops_the_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``warn_query_credentials=False`` is not a quieter check: an unlisted host is still refused
    on both seams, and the only line missing is the query-credential one."""
    egress = EgressSettings(allowed_http=["other.example.invalid"])
    url = _KEYED.format(v=1)
    for warn in (True, False):
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            with pytest.raises(WiringError, match="not in the"):
                check_egress_allowed(_rest(url), egress, warn_query_credentials=warn)
            with pytest.raises(WiringError, match="not in the"):
                check_fhir_lookup_allowed("LK", {"url": url}, egress, warn_query_credentials=warn)
        # The control is the True pass: the same egress reaches the warning on both seams.
        assert _warned(caplog, "outbound 'OB_REST'") == int(warn)
        assert _warned(caplog, "FhirLookup 'LK'") == int(warn)
        messages = [r.getMessage() for r in caplog.records]
        assert any("egress denied: outbound 'OB_REST'" in m for m in messages)
        assert any("connect denied: FhirLookup 'LK'" in m for m in messages)


async def test_a_start_and_an_operator_start_still_warn_once(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Builds with no build check before them keep the warning. This exercises two of them: the
    engine start, for an outbound and a FhirLookup, and the operator start of a lane ``auto_start``
    left unbuilt. docs/SECURITY-LOOSENING.md is the source of record for where the warning fires."""
    reg = _reload_graph(fhir=True)
    spec = ConnectionSpec(type=ConnectorType.REST, settings={"url": _KEYED.format(v=1)})
    reg.add_outbound(build_outbound_connection("OB_OFF", spec, auto_start=False))
    runner = _reload_runner(reload_store, reg)
    try:
        with caplog.at_level(logging.WARNING):
            await runner.start()
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "FhirLookup 'LK'") == 1
        assert "OB_OFF" not in runner._destinations
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.start_outbound("OB_OFF")
        assert "OB_OFF" in runner._destinations
        assert _warned(caplog, "outbound 'OB_OFF'") == 1
    finally:
        await runner.stop()


@pytest.mark.parametrize("warn", [True, False])
async def test_a_failed_fhir_lookup_keeps_one_warning_and_each_survivor_one_at_start(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture, warn: bool
) -> None:
    """Two lookups fail to resolve, so the whole-graph build is skipped, each lookup that resolved
    builds alone, and the survivors build again. Each lookup whose ``url`` resolved logs one line.

    The control this pins is the ASVS 14.2.1 record for a lookup that is down: ``LK_BAD``'s
    settings resolved and its build failed, and ``LK_TOKEN``'s URL resolved while another setting
    did not. Each keeps its one WARNING, so an ``env()`` URL with a query credential is named while
    the lookup is isolated. Warning only for the survivors fails the ``LK_BAD`` count, and warning
    only for fully resolved settings fails the ``LK_TOKEN`` count. ``LK_UNSET``'s ``env()`` URL
    never resolved, so there is no URL to read and it logs none. The ``warn=False`` case is the
    start ``Engine.reload_detail`` makes after its build check: every count is zero there, on the
    isolation path as on the healthy one."""
    reg = Registry()
    lookups: dict[str, dict[str, str | EnvRef]] = {
        "LK_A": {"url": _LOOKUP_URL},
        "LK_BAD": {"url": "ftp://fhir.example.invalid/R4?api_key=PLACEHOLDER"},  # not http(s)
        "LK_TOKEN": {"url": _LOOKUP_URL, "bearer_token": EnvRef("MEFOR_UNSET_LOOKUP_TOKEN")},
        "LK_UNSET": {"url": EnvRef("MEFOR_UNSET_LOOKUP_URL")},
        "LK_Z": {"url": _LOOKUP_URL},
    }
    for name, settings in lookups.items():
        reg.add_fhir_lookup(FhirLookupSpec(name=name, settings=settings))
    runner = _reload_runner(reload_store, reg)
    try:
        with caplog.at_level(logging.INFO):
            await runner.start(warn_query_credentials=warn)
        assert sorted(runner.degraded_fhir_lookups()) == ["LK_BAD", "LK_TOKEN", "LK_UNSET"]
        for name in ("LK_A", "LK_Z", "LK_BAD", "LK_TOKEN"):
            assert _warned(caplog, f"FhirLookup {name!r}") == int(warn), name
        assert _warned(caplog, "FhirLookup 'LK_UNSET'") == 0
        # The INFO line says why LK_UNSET has no WARNING, and only for it.
        unread = [m for m in _messages(caplog) if "its url did not resolve" in m]
        assert unread == ["FhirLookup 'LK_UNSET': " + _UNREAD] * int(warn)
    finally:
        await runner.stop()


async def test_a_raising_warning_step_isolates_its_lookup_and_the_rest_start(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control is ADR 0031 / vault BACKLOG #3008 isolation: one lookup's failure costs that
    lookup only. The warning step runs outside the build, so a failure there must be isolated as
    a build failure is. Here it raises for ``LK_BOOM`` only. The start completes, ``LK_BOOM`` is
    degraded, and ``LK_A`` and ``LK_Z`` are built and keep their one WARNING each. Letting the
    warning step raise out of the resolve loop fails the start, and this test."""
    real = warn_url_query_credentials

    def warn_or_raise(label: str, settings: Any) -> None:
        if "LK_BOOM" in label:
            raise RuntimeError("synthetic failure in the warning step")
        real(label, settings)

    monkeypatch.setattr(
        "messagefoundry.pipeline.wiring_runner.warn_url_query_credentials", warn_or_raise
    )
    reg = Registry()
    for name in ("LK_A", "LK_BOOM", "LK_Z"):
        reg.add_fhir_lookup(FhirLookupSpec(name=name, settings={"url": _LOOKUP_URL}))
    runner = _reload_runner(reload_store, reg)
    try:
        with caplog.at_level(logging.WARNING):
            await runner.start()
        assert runner._running
        assert list(runner.degraded_fhir_lookups()) == ["LK_BOOM"]
        assert runner._fhir_lookup_executor is not None
        assert runner.fhir_lookup_failed("LK_A") is None
        assert runner.fhir_lookup_failed("LK_Z") is None
        assert _warned(caplog, "FhirLookup 'LK_A'") == 1
        assert _warned(caplog, "FhirLookup 'LK_Z'") == 1
    finally:
        await runner.stop()


async def test_a_failed_build_alone_leaves_each_lookup_one_warning_at_start(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Every lookup resolves, so the whole-graph build runs and fails at ``LK_BAD``, then each
    lookup builds alone, then the survivors build again. Each build used to warn for every lookup
    it was given: three lines for a survivor and two for ``LK_BAD``. Warning inside any of those
    builds fails these counts."""
    reg = Registry()
    lookups = {
        "LK_A": _LOOKUP_URL,
        "LK_BAD": "ftp://fhir.example.invalid/R4?api_key=PLACEHOLDER",  # not http or https
        "LK_Z": _LOOKUP_URL,
    }
    for name, url in lookups.items():
        reg.add_fhir_lookup(FhirLookupSpec(name=name, settings={"url": url}))
    runner = _reload_runner(reload_store, reg)
    try:
        with caplog.at_level(logging.WARNING):
            await runner.start()
        assert list(runner.degraded_fhir_lookups()) == ["LK_BAD"]
        for name in lookups:
            assert _warned(caplog, f"FhirLookup {name!r}") == 1, name
    finally:
        await runner.stop()


async def test_a_reload_of_an_unstarted_runner_warns_and_its_later_start_warns_again(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """docs/SECURITY-LOOSENING.md states it: a reload of a runner that exists but is not started
    runs its build check and makes no builds, so the later start, which has no build check before
    it, logs the WARNING again."""
    runner = _reload_runner(reload_store, _reload_graph(v=1))
    try:
        with caplog.at_level(logging.WARNING):
            await runner.reload(_reload_graph(v=2, fhir=True))
        assert "OB_KEYED" not in runner._destinations  # no build
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "FhirLookup 'LK'") == 1
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.start()
        assert "OB_KEYED" in runner._destinations
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "FhirLookup 'LK'") == 1
    finally:
        await runner.stop()


async def test_an_unlisted_forward_proxy_still_logs_one_warning_for_an_outbound_and_a_lookup(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """docs/SECURITY-LOOSENING.md states it: the egress check logs the WARNING before any of its
    refusals, so a lane or a lookup it refuses over an unlisted forward proxy is still recorded
    while it is down. Before, the proxy refusal came first and both logged none."""
    proxy = {"proxy_url": "http://proxy.example.invalid:3128"}
    reg = Registry()
    spec = ConnectionSpec(type=ConnectorType.REST, settings={"url": _KEYED.format(v=1), **proxy})
    reg.add_outbound(build_outbound_connection("OB_KEYED", spec))
    reg.add_fhir_lookup(FhirLookupSpec(name="LK", settings={"url": _LOOKUP_URL, **proxy}))
    runner = _reload_runner(reload_store, reg)
    try:
        with caplog.at_level(logging.WARNING):
            await runner.start()
        assert "OB_KEYED" not in runner._destinations
        assert list(runner.degraded_fhir_lookups()) == ["LK"]
        messages = [r.getMessage() for r in caplog.records]
        assert any("forward proxy set with an empty" in m for m in messages)
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "FhirLookup 'LK'") == 1
    finally:
        await runner.stop()


# --- a schedule dropped from a calendar-parked lane (vault BACKLOG #3766 item 2) ----------------


_WINDOW = Schedule(
    windows=[ActiveWindow(days=frozenset({0}), start=time(8), end=time(17), timezone="UTC")]
)
_OUTSIDE = datetime(2026, 7, 13, 20, tzinfo=UTC)  # a Monday, past the window
_INSIDE = datetime(2026, 7, 13, 9, tzinfo=UTC)  # the same Monday, in it


async def _park(runner: RegistryRunner) -> None:
    """Close the window on ``OB_KEYED`` deterministically, as the scheduler's tick would."""
    await runner._reconcile_schedule("OB_KEYED", "outbound", _WINDOW)
    assert "OB_KEYED" in runner._schedule_parked


@pytest.mark.parametrize("claim_mode", ["pooled", "per_lane"])
async def test_a_reload_that_drops_the_schedule_warns_once_for_a_lane_with_no_connector(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture, claim_mode: str
) -> None:
    """The row's concern. The resume builds through the warning default of
    ``_ensure_destination_built``, and ``_reconcile_outbounds`` has built the lane by then, so the
    resume finds a connector and builds nothing. The lane has none here because its first build
    failed, and the reload's new URL is what cures it."""
    runner = _reload_runner(
        reload_store,
        _reload_graph(url=EnvRef("MEFOR_UNSET_URL"), schedule=_WINDOW),
        schedule_clock=lambda: _OUTSIDE,
        schedule_tick=3600.0,
        claim_mode=claim_mode,
    )
    try:
        await runner.start()
        assert "OB_KEYED" not in runner._destinations  # the first build failed
        await _park(runner)
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.reload(_reload_graph(v=1))
        assert "OB_KEYED" in runner._destinations
        assert "OB_KEYED" not in runner._schedule_parked  # the resume ran
        assert runner.outbound_running("OB_KEYED")
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
    finally:
        await runner.stop()


async def test_a_reload_that_drops_the_schedule_warns_once_for_a_lane_with_its_connector(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: the park kept the connector, so the one line is the build check's."""
    runner = _reload_runner(
        reload_store,
        _reload_graph(schedule=_WINDOW),
        schedule_clock=lambda: _OUTSIDE,
        schedule_tick=3600.0,
    )
    try:
        await runner.start()
        before = runner._destinations["OB_KEYED"]
        await _park(runner)
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.reload(_reload_graph())
        assert runner._destinations["OB_KEYED"] is before
        assert "OB_KEYED" not in runner._schedule_parked
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
    finally:
        await runner.stop()


async def test_a_window_open_that_builds_the_lane_warns(
    reload_store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The warning default of ``_ensure_destination_built``, which a window open builds through: no
    build check runs before a window open, so this build is the only one to warn. It is why the
    resume path above passes no flag."""
    now = [_OUTSIDE]
    runner = _reload_runner(
        reload_store,
        _reload_graph(url=EnvRef("MEFOR_LATE_URL"), schedule=_WINDOW),
        schedule_clock=lambda: now[0],
        schedule_tick=3600.0,
    )
    try:
        await runner.start()
        await _park(runner)
        runner._env_values = {"MEFOR_LATE_URL": _KEYED.format(v=1)}  # the cause, since cured
        now[0] = _INSIDE
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner._reconcile_schedule("OB_KEYED", "outbound", _WINDOW)
        assert "OB_KEYED" in runner._destinations
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
    finally:
        await runner.stop()


# --- through the engine: a reload with no runner yet, and a plain start (vault BACKLOG #2910) ---


_ENGINE_CONFIG = """
from messagefoundry import FhirLookup, File, Rest, Send, handler, inbound, outbound, router

inbound("IB", File(directory={inbox!r}, pattern="*.hl7", poll_seconds=0.02), router="r")
outbound("OB_KEYED", Rest(url="https://p.example.invalid/x?key=PLACEHOLDER"))
outbound("OB_OFF", Rest(url="https://p.example.invalid/x?key=PLACEHOLDER"), auto_start=False)
FhirLookup("LK", url="https://fhir.example.invalid/R4?api_key=PLACEHOLDER")


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_KEYED", msg)
"""


async def _engine(tmp_path: Path) -> Engine:
    return await Engine.create(
        tmp_path / "engine.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )


def _engine_config(tmp_path: Path) -> Path:
    inbox = tmp_path / "in"
    inbox.mkdir()
    return _write(tmp_path, _ENGINE_CONFIG.format(inbox=str(inbox)))


async def test_a_reload_with_no_runner_yet_warns_once_and_the_start_keeps_no_silence(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``Engine.reload_detail`` runs the build check, then a start: both warned. The flag is on the
    START side, for this path only: ``OB_OFF`` is built in the check alone, so a quiet check would
    lose its line. And it lasts one call: the operator start that first builds ``OB_OFF`` warns."""
    cfg = _engine_config(tmp_path)
    eng = await _engine(tmp_path)
    try:
        await eng.start()
        assert eng.registry_runner is None
        with caplog.at_level(logging.WARNING):
            outcome = await eng.reload_detail(cfg)
        assert outcome.applied
        runner = eng.registry_runner
        assert runner is not None and "OB_KEYED" in runner._destinations
        assert "OB_OFF" not in runner._destinations
        assert runner._fhir_lookup_executor is not None
        for label in ("outbound 'OB_KEYED'", "outbound 'OB_OFF'", "FhirLookup 'LK'"):
            assert _warned(caplog, label) == 1, label
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            await runner.start_outbound("OB_OFF")
        assert "OB_OFF" in runner._destinations
        assert _warned(caplog, "outbound 'OB_OFF'") == 1
    finally:
        await eng.stop()


async def test_a_plain_engine_start_warns_then_a_reload_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: no build check runs before an ``Engine.start``, so it keeps the warning. Its
    ``auto_start=False`` lane is not built, so that lane logs nothing until a reload's check."""
    cfg = _engine_config(tmp_path)
    eng = await _engine(tmp_path)
    try:
        eng.add_registry(load_config(cfg))
        with caplog.at_level(logging.WARNING):
            await eng.start()
        assert _warned(caplog, "outbound 'OB_KEYED'") == 1
        assert _warned(caplog, "FhirLookup 'LK'") == 1
        assert _warned(caplog, "outbound 'OB_OFF'") == 0
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            outcome = await eng.reload_detail(cfg)
        assert outcome.applied
        for label in ("outbound 'OB_KEYED'", "outbound 'OB_OFF'", "FhirLookup 'LK'"):
            assert _warned(caplog, label) == 1, label
    finally:
        await eng.stop()
