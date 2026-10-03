# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A credential in an outbound ``url``'s query string is a RECORDED loosening (ASVS 14.2.1).

The vault re-read of 2026-10-01 found it accepted with no line anywhere: ``refuse_url_credentials``
covers the userinfo and never the query. It is WARNED and reported rather than refused; the reason is
on ``transports.egress.warn_url_query_credentials``. Every positive arm has a benign-parameter
control, so a test is not green because the detector names every parameter.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    Registry,
    build_outbound_connection,
    query_credential_hops,
)
from messagefoundry.secretscrub import credential_query_params
from messagefoundry.transports.egress import check_egress_allowed

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
