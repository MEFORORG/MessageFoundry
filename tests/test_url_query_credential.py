# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A credential in an outbound ``url``'s query string is a RECORDED loosening (ASVS 14.2.1).

The vault re-read of 2026-10-01 found it accepted with no line anywhere: ``refuse_url_credentials``
covers the userinfo and never the query. It is WARNED and reported rather than refused; the reason is
on ``pipeline.wiring_runner.warn_url_query_credentials``. Every positive arm has a benign-parameter
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
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.secretscrub import credential_query_params

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


def test_redacted_settings_masks_an_env_default_url_and_other_url_keys() -> None:
    """The env() DEFAULT and a URL-suffixed key other than ``url`` reach /metadata too."""
    from messagefoundry.config.wiring import env, redacted_settings

    shown = redacted_settings(
        {
            "url": env("MEFOR_URL", default="https://u:pw@p.example.invalid/x?key=SYNTHETIC-7"),
            "smart_token_url": "https://t.example.invalid/token?client_secret=SYNTHETIC-8",
        }
    )
    assert shown["url"]["default"] == "https://u:***@p.example.invalid/x?key=***"
    assert shown["smart_token_url"] == "https://t.example.invalid/token?client_secret=***"


def test_a_query_at_sign_with_no_colon_before_it_leaves_the_host_alone() -> None:
    """A query ``@`` with no ``:`` ahead of it gives urllib's proxy parser a user and no password,
    so only the query key is masked. CORRECTED (Lander QA on PR 1912): this test also pinned a port
    and an IPv6 host as untouched. urllib reads a PASSWORD in both (``8443/x?email=a``), so the mask
    now follows it and they are in the parity table below instead."""
    from messagefoundry.config.wiring import redacted_settings

    url = "https://h.example.invalid/x?email=a@b.example.invalid&key=SYNTHETIC-9"
    assert redacted_settings({"url": url})["url"] == url.replace("SYNTHETIC-9", "***")


#: (case, URL). Each one is run through urllib's own proxy parser in the parity test below.
_PARITY_CASES = [
    ("? in password", "http://user:p?ss@proxy.example.invalid:3128"),
    ("# in password", "http://user:p#ss@proxy.example.invalid:3128"),
    ("/ in password", "http://user:pa/ss@proxy.example.invalid:3128"),
    ("@ in password", "http://user:a@b?c@proxy.example.invalid:3128"),
    ("digits and / in password", "http://user:1234/5@proxy.example.invalid"),
    ("@ in user", "http://alice@corp:p?ss@proxy.example.invalid:3128"),
    ("IPv6 host with a query @", "https://[::1]/x?email=a@b.example.invalid&key=SYNTHETIC-11"),
    ("path @ after a port", "https://h.example.invalid:8443/users/a@b.example.invalid"),
    ("query @ after a port", "https://h.example.invalid:8443/x?email=a@b.example.invalid"),
    ("query @ after a time", "https://h.example.invalid/x?t=12:00&email=a@b.example.invalid"),
    ("path @ with no port", "https://h.example.invalid/users/a@b.example.invalid"),
    ("no scheme", "user:pw-no-scheme@proxy.example.invalid:3128"),
    ("no scheme, no password", "user@proxy.example.invalid:3128"),
    ("port, password and path", "http://user:pw-port@proxy.example.invalid:3128/x"),
    ("no userinfo", "http://proxy.example.invalid:3128/path?x=1#f"),
    ("no userinfo, no scheme", "proxy.example.invalid:3128"),
    ("user, no password", "https://token@h.example.invalid/x"),
    ("empty password", "http://user:@proxy.example.invalid:3128"),
    ("empty user", "http://:pw-empty-user@proxy.example.invalid:3128"),
    # Review of f62c0df1b6: a ":" and a later "@" made the proxy reader's USER swallow the query.
    (
        "query key inside the proxy user",
        "https://api.example.invalid/v1/export?api_key=SYNTHETIC-12&from=2026-01-01T00:00:00Z"
        "&notify=ops@example.invalid",
    ),
    (
        "query key, at-time-email",
        "https://h.example.invalid/x?client_secret=SYNTHETIC-13&at=10:00&by=a@b",
    ),
    # ... and a "?" in the fragment or a late value sent the leftover down the wrong path.
    (
        "swallowed query, ? in fragment",
        "https://h.example.invalid:8443/x?email=a@b.example.invalid&key=SYNTHETIC-14#frag?z",
    ),
    (
        "swallowed query, ? in a value",
        "https://h.example.invalid:8443/x?email=a@b&key=SYNTHETIC-15&q=what?",
    ),
]


@pytest.mark.parametrize(("case", "url"), _PARITY_CASES, ids=[c for c, _ in _PARITY_CASES])
def test_the_userinfo_mask_hides_every_password_urllib_reads(case: str, url: str) -> None:
    """Parity with urllib's proxy parser, the code that SENDS a proxy_url's password. Lander QA on
    PR 1912: a hand-rolled rule showed ``user:1234/5@proxy``, whose password urllib reads as
    ``1234/5``. Whatever password urllib reads must never appear in the masked view, and a URL in
    which it reads none must come back unchanged apart from a masked query key."""
    import urllib.parse
    import urllib.request

    from messagefoundry.config.wiring import redacted_settings
    from messagefoundry.secretscrub import _is_credential_param, mask_credential_query

    _scheme, _user, password, _hostport = urllib.request._parse_proxy(url)  # type: ignore[attr-defined]
    # Two readers' passwords: urllib's proxy parser, and urlsplit's netloc for a dialled URL.
    passwords = [p for p in (password, urllib.parse.urlsplit(url).password) if p]
    for key in ("proxy_url", "url"):  # a proxy key and a dialled-URL key mask alike
        shown = redacted_settings({key: url})[key]
        # Every query credential the detector's name test accepts stays hidden, whichever reader
        # cut the URL. Raw names from parse_qsl, not the detector's display names.
        assert "SYNTHETIC" not in shown, (case, shown)
        for name, val in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query):
            if _is_credential_param(name) and val:
                assert val not in shown, (case, name, shown)
        # A one- or two-character password can occur in the host by chance; the span tests in
        # this file pin those shapes exactly.
        for secret in passwords:
            if len(secret) >= 3:
                assert secret not in shown, (case, shown)
        if passwords:
            assert "***" in shown, case
        else:
            # Neither reader finds a password: the view is the query mask alone.
            assert shown == mask_credential_query(url), (case, shown)


def test_the_parser_mirror_agrees_with_urllib_over_generated_strings() -> None:
    """The table above holds the shapes someone thought of. This drives the mirror and urllib's
    parser over seeded random strings built from the characters that move its spans, and requires
    the same answer: a password exactly when urllib reads one, the same user, and the same host."""
    import random
    import urllib.request

    from messagefoundry.config.wiring import _proxy_userinfo_split

    rng = random.Random(1912)
    compared = with_password = 0
    for alphabet in ("ab:/@?#[]1.", "h:/@?#&=k12.", "u:p/@x"):
        for _ in range(20000):
            value = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 16)))
            got = _proxy_userinfo_split(value)
            try:
                _scheme, user, password, hostport = urllib.request._parse_proxy(value)  # type: ignore[attr-defined]
            except ValueError:
                assert got is None, value
                continue
            compared += 1
            if not password:  # none, or empty: no secret to mask
                assert got is None, value
            else:
                with_password += 1
                assert got is not None and got[1] == user and got[2].startswith(hostport), value
    # Liveness: the generator must reach both arms, or the agreement above says nothing.
    assert compared > 10000 and with_password > 1000, (compared, with_password)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # urllib's Request unquotes the host, so "%40" ends a userinfo as "@" does.
        ("http://user:SYNTH-PCT%40h.example.invalid/x", "http://user:***%40h.example.invalid/x"),
        # urlsplit drops a tab before it finds "//", and then reads a password.
        ("http:/\t/user:SYNTH-TAB@h.example.invalid/x", "http:/\t/user:***@h.example.invalid/x"),
        # Two spans that touch merge into one "***".
        ("http://h?key=x:&y@z/", "http://h?key=***@z/"),
    ],
)
def test_the_mask_models_more_readers_than_the_two_parsers(url: str, expected: str) -> None:
    """Review of 2544705869: each of these hid a password, or split one mask in two."""
    from messagefoundry.config.wiring import redacted_settings

    assert redacted_settings({"url": url})["url"] == expected


def test_a_query_span_nested_inside_a_password_merges_into_one_mask() -> None:
    """The proxy reader's password ``x?key=S&tail`` contains a query segment's value. The two spans
    must merge; a merge that stepped back to the inner span's end would show ``&tail``."""
    from messagefoundry.config.wiring import redacted_settings

    url = "http://user:x?key=SYNTHETIC-16&tail@proxy.example.invalid:3128"
    assert redacted_settings({"proxy_url": url})["proxy_url"] == (
        "http://user:***@proxy.example.invalid:3128"
    )


def test_the_composed_mask_never_shows_a_named_key_or_a_read_password() -> None:
    """The property the review of f62c0df1b6 asked for, over the COMPOSED mask: wherever a seeded
    generator puts ``key=QZXJ`` among the characters that move every reader's spans, a value the
    detector names, or one inside a password urllib reads, is never shown."""
    import random
    import urllib.parse
    import urllib.request

    from messagefoundry.config.wiring import redacted_settings

    rng = random.Random(14_2_1)
    named = in_password = in_netloc = 0
    for _ in range(30000):
        # Tab, LF and "%40" too (review of 2544705869): urlsplit drops the first two before it
        # reads, and urllib's Request unquotes the host, so each moves a reader's spans.
        alphabets = ("h:/@?#&=1.", "h:/@?#&=1.\t\n", "h:/@?&=1.;")
        noise = rng.choice(alphabets) + "%40" * rng.randint(0, 1)
        head = "".join(rng.choice(noise) for _ in range(rng.randint(0, 10)))
        tail = "".join(rng.choice(noise.replace("=", "")) for _ in range(rng.randint(0, 10)))
        url = f"http://{head}{rng.choice('?&')}key=QZXJ{tail}"
        shown = redacted_settings({"proxy_url": url})["proxy_url"]
        if "key" in credential_query_params(url):
            named += 1
            assert "QZXJ" not in shown, (url, shown)
        try:
            password = urllib.request._parse_proxy(url)[2]  # type: ignore[attr-defined]
        except ValueError:
            continue
        if password and "QZXJ" in password:
            in_password += 1
            assert "QZXJ" not in shown, (url, shown)
        try:
            netloc_password = urllib.parse.urlsplit(url).password
        except ValueError:
            continue
        if netloc_password and "QZXJ" in netloc_password:
            in_netloc += 1
            assert "QZXJ" not in shown, (url, shown)
    assert named > 1000 and in_password > 100 and in_netloc > 20, (named, in_password, in_netloc)


@pytest.mark.parametrize(
    ("user", "password"),
    [
        ("user", "p?ss"),
        ("user", "p#ss"),
        ("user", "pa/ss"),
        ("user", "a@b?c"),
        ("alice@corp", "p?ss"),
    ],
)
def test_userinfo_mask_fails_toward_masking_a_password_holding_a_delimiter(
    user: str, password: str
) -> None:
    """Lander QA on 4e1c148c5e, and review round 3: these passwords came back whole or in part,
    and urllib's proxy parser accepts them."""
    from messagefoundry.config.wiring import redacted_settings

    shown = redacted_settings({"proxy_url": f"http://{user}:{password}@proxy.example.invalid:3128"})
    assert shown["proxy_url"] == f"http://{user}:***@proxy.example.invalid:3128"


def test_a_query_credential_is_masked_behind_a_password_holding_a_question_mark() -> None:
    """Both masks read the original string and their spans are joined, so a "?" in the password
    cannot move the span the query mask reads."""
    from messagefoundry.config.wiring import redacted_settings

    url = "http://user:p?ss@h.example.invalid/x?key=SYNTHETIC-10"
    assert redacted_settings({"url": url})["url"] == "http://user:***@h.example.invalid/x?key=***"


def test_userinfo_mask_leaves_a_url_with_no_userinfo_alone() -> None:
    """Controls that reach the parser mirror: an "@" after the path with no ":" ahead of it, and no
    "@" at all. CORRECTED: a path "@" after a PORT was here too; urllib reads a password there."""
    from messagefoundry.config.wiring import redacted_settings

    for url in (
        "http://proxy.example.invalid:3128/path?x=1#f",
        "https://h.example.invalid/users/a@b.example.invalid",
    ):
        assert redacted_settings({"proxy_url": url})["proxy_url"] == url


def test_mask_fails_toward_masking_when_urlsplit_strips_a_control_character() -> None:
    """Lander QA: urlsplit strips tab, CR and LF, so its query is not a substring of the URL as
    written. The detector still named the key; the mask must not show its value."""
    from messagefoundry.secretscrub import mask_credential_query

    url = "https://h.example.invalid/p?key=SE\tCRET&fmt=json"
    assert credential_query_params(url) == ["key"]
    assert mask_credential_query(url) == "https://h.example.invalid/p?key=***&fmt=json"
    # A tab inside the NAME, which urlsplit drops before the detector sees it.
    url = "https://h.example.invalid/p?api_\tkey=SECRET&fmt=json"
    assert credential_query_params(url) == ["api_key"]
    assert mask_credential_query(url) == "https://h.example.invalid/p?api_\tkey=***&fmt=json"
    # A copy of the query in the fragment must not draw the mask away from the real one; both are
    # masked, since the span scan judges every segment wherever it sits.
    url = "https://h.example.invalid/p?key=SE\tCRET#?key=SECRET"
    assert mask_credential_query(url) == "https://h.example.invalid/p?key=***#?key=***"
    # A tab inside a percent-escape in the name (review of 2544705869): urlsplit drops it before
    # parse_qsl decodes the name to api_key, so the span scan must drop it too.
    url = "https://h.example.invalid/x?api%5\tFkey=TABESC2"
    assert credential_query_params(url) == ["api_key"]
    assert "TABESC2" not in mask_credential_query(url)


def test_the_span_scan_masks_more_than_the_detector_names() -> None:
    """CORRECTED (review of 2544705869): this test pinned a fragment ``?key=`` as left alone. The
    span scan now masks every segment that looks like a credential, wherever it sits, which fails
    toward masking; the detector, which feeds the warning, still reads the query alone."""
    from messagefoundry.secretscrub import mask_credential_query

    url = "https://p.example.invalid/x#frag?key=S"
    assert credential_query_params(url) == []
    assert mask_credential_query(url) == "https://p.example.invalid/x#frag?key=***"


@pytest.mark.parametrize(
    ("text", "spans"),
    [
        ("https://h/x?key=abc&fmt=json", [(16, 19)]),
        ("https://h/x?key=&fmt=json", []),  # an empty value has no span
        ("https://h/x?fmt=json#key=abc", [(25, 28)]),  # "#" starts a segment
        ("https://h/x?key=a?b&z=1", [(16, 19)]),  # "?" does not end a value; "&" does
        ("https://h/app;jsessionid=ABC?x=1", [(25, 32)]),  # ";" starts a segment
        ("https://h/x?a=1;api_key=SEMI", [(24, 28)]),
        ("https://h/x?keyword=abc", []),  # control: not a credential name
    ],
)
def test_credential_value_spans_contract(text: str, spans: list[tuple[int, int]]) -> None:
    from messagefoundry.secretscrub import credential_value_spans

    assert credential_value_spans(text) == spans


def test_redacted_settings_masks_the_query_value_and_keeps_the_rest() -> None:
    """``GET /metadata`` and ``graph --json`` serve settings through ``redacted_settings``. Before the
    review fix it masked only the userinfo, so the key the WARNING named was served verbatim."""
    from messagefoundry.config.wiring import redacted_settings

    url = "https://u:pw@p.example.invalid/x?key=SYNTHETIC-5&fmt=json#frag"
    shown = redacted_settings({"url": url})["url"]
    assert shown == "https://u:***@p.example.invalid/x?key=***&fmt=json#frag"
    # Control: a benign query is untouched.
    benign = "https://p.example.invalid/x?fmt=json&keyword=lab"
    assert redacted_settings({"url": benign})["url"] == benign


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
            _rest("https://p.example.invalid/x?key=SYNTHETIC-SECRET-2&fmt=json"), EgressSettings()
        )
    [line] = [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]
    assert "'OB_REST'" in line and "(parameter(s) key)" in line
    assert "SYNTHETIC-SECRET-2" not in line and "p.example.invalid" not in line


def test_build_with_a_benign_query_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(
            _rest("https://p.example.invalid/x?fmt=json&keyword=lab"), EgressSettings()
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
    from messagefoundry.pipeline.wiring_runner import check_fhir_lookup_allowed

    reg = _registry()
    url = "https://fhir.example.invalid/R4?api_key=SYNTHETIC-6"
    reg.add_fhir_lookup(FhirLookupSpec(name="LK", settings={"url": url}))
    assert ("fhir_lookup:LK", "api_key") in query_credential_hops(reg)
    with caplog.at_level(logging.WARNING):
        check_fhir_lookup_allowed("LK", {"url": url}, EgressSettings())
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
