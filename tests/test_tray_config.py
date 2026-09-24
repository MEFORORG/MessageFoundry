# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray config compose + engine-URL discovery (ADR 0113 §5) — pure, runs on any OS."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from messagefoundry.tray.config import (
    DEFAULT_ENGINE_URL,
    DEFAULT_SERVICE_NAME,
    ServiceRegistryInfo,
    _split_command_line,
    build_engine_url,
    compose_config,
    engine_serves_https,
    generated_cert_path,
    is_local_engine,
    is_tls_url,
    load_config,
    parse_serve_args,
    parse_service_config_arg,
    service_toml_path,
)

_SPLIT_CASES = [
    # The BACKLOG #1565 case: str.split() kept the quotes AND split inside them, so this
    # yielded '"C:\\Program' and 'Files\\MF\\x.toml"' -- two paths that cannot exist.
    (
        'serve --service-config "C:\\Program Files\\MF\\x.toml"',
        ["serve", "--service-config", "C:\\Program Files\\MF\\x.toml"],
    ),
    # A quoted path with NO space broke identically, so the defect is the quoting, not spaces.
    ('--service-config "C:\\svc\\x.toml"', ["--service-config", "C:\\svc\\x.toml"]),
    # The equals form, quoted: one token, which _iter_options splits afterwards.
    ('--service-config="C:\\P F\\x.toml"', ["--service-config=C:\\P F\\x.toml"]),
    # Unquoted backslash paths survive untouched -- the case that works today, and the one
    # shlex(posix=True) would destroy ("C:datax.toml").
    ("C:\\data\\x.toml", ["C:\\data\\x.toml"]),
    ("\\\\server\\share\\x.toml", ["\\\\server\\share\\x.toml"]),
    # Windows separators are space and tab only; runs of them collapse.
    ("serve\t--host\t127.0.0.1", ["serve", "--host", "127.0.0.1"]),
    ("   serve    --host  ::1   ", ["serve", "--host", "::1"]),
    ("", []),
    ("   ", []),
    # 2n backslashes before a quote halve and toggle the run; 2n+1 escape the quote itself.
    ('"C:\\MF\\\\"', ["C:\\MF\\"]),
    ('x\\\\"y z', ["x\\y z"]),
    ('x\\\\\\"y z', ['x\\"y', "z"]),
    # A doubled quote inside a run is one literal quote and ENDS the run -- see the tokenizer's
    # docstring, where CommandLineToArgvW parts company with the MSVCRT rule. Here that makes the
    # LATER quote reopen a run, so the space after 'b' is literal and this is ONE argument.
    # Verified against shell32 rather than reasoned: the first expectation written here was
    # ['a"b', 'c'], and the oracle disagreed.
    ('"a""b" c', ['a"b c']),
    ('a """ b', ["a", '"', "b"]),
    ('""""', ['"']),
    ('"""""', ['"']),
    # Malformed quoting is tolerated rather than raising: the run ends with the string.
    ('--service-config "C:\\svc\\x.toml', ["--service-config", "C:\\svc\\x.toml"]),
    # An empty quoted value is a real, empty argument.
    ('--service-config ""', ["--service-config", ""]),
    # Apostrophes are NOT a Windows quoting form: they stay in the token, so the path really is
    # named with them. Pinned because it looks like a gap and is not one.
    ("--service-config 'C:\\q\\x.toml'", ["--service-config", "'C:\\q\\x.toml'"]),
    ('"a b" "c d"', ["a b", "c d"]),
]


@pytest.mark.parametrize(("line", "argv"), _SPLIT_CASES)
def test_split_command_line(line: str, argv: list[str]) -> None:
    assert _split_command_line(line) == argv


# Lines the oracle below also checks, where the real function is the only expectation worth
# writing down: quoting no operator produces, plus the quoted host and port from the row.
_ORACLE_EXTRA = [
    'serve --host "127.0.0.1" --port "8765"',
    'serve --service-config "a""b.toml"',
    "serve\t--host\t127.0.0.1\t--port\t8765",
    " leading and trailing ",
]


@pytest.mark.skipif(sys.platform != "win32", reason="shell32.CommandLineToArgvW is Windows-only")
def test_split_command_line_matches_the_win32_oracle() -> None:
    """Differential against ``shell32.CommandLineToArgvW`` -- the rules, not a reading of them.

    The tokenizer itself stays pure Python (the tray is stdlib-ctypes-only and this module's core
    must be unit-testable on any OS), so ctypes appears HERE and nowhere in the shipped path. The
    oracle parses ``argv[0]`` under its own rules, so every case is prefixed with a bare program
    token and compared from element 1.

    It runs over ``_SPLIT_CASES`` itself, so a case added to the table above is checked against the
    real function too rather than only against a hand-written expectation.
    """
    import ctypes
    import random
    from ctypes import wintypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    def oracle(params: str) -> list[str]:
        count = ctypes.c_int(0)
        argv = shell32.CommandLineToArgvW("prog " + params, ctypes.byref(count))
        if not argv:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return [argv[i] for i in range(1, count.value)]
        finally:
            kernel32.LocalFree(ctypes.cast(argv, wintypes.HLOCAL))

    for case in [line for line, _ in _SPLIT_CASES] + _ORACLE_EXTRA:
        assert _split_command_line(case) == oracle(case), f"curated case {case!r}"

    # Seeded fuzz over the characters the rules turn on, so a regression in any branch shows up as
    # a concrete counter-example rather than as a gap in the curated list.
    rng = random.Random(1565)
    alphabet = ' \t"\\abC:.=-'
    for _ in range(4000):
        case = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
        assert _split_command_line(case) == oracle(case), f"fuzz case {case!r}"


@pytest.mark.parametrize(
    ("args", "host", "port"),
    [
        ("serve --config C:\\cfg --host 127.0.0.1 --port 8765 --env prod", "127.0.0.1", 8765),
        ("serve --host=10.0.0.5 --port=9000", "10.0.0.5", 9000),
        ("serve --config C:\\cfg", None, None),
        ("serve --host 10.1.2.3", "10.1.2.3", None),
        ("serve --port 70000", None, None),  # out of range
        ("serve --port notanint", None, None),
        ("serve --host bad;host --port 8765", None, 8765),  # ';' is not a valid host char
        # BACKLOG #1565: a quoted host failed the host regex and a quoted port failed int(), so the
        # discovered URL was wrong by more than its scheme.
        ('serve --host "127.0.0.1" --port "8765"', "127.0.0.1", 8765),
        ('serve --host="10.0.0.5" --port="9000"', "10.0.0.5", 9000),
    ],
)
def test_parse_serve_args(args: str, host: str | None, port: int | None) -> None:
    assert parse_serve_args(args) == (host, port)


def test_build_engine_url() -> None:
    assert build_engine_url("127.0.0.1", 8765) == "http://127.0.0.1:8765"
    assert build_engine_url(None, 8765) is None
    assert build_engine_url("127.0.0.1", None) is None
    assert build_engine_url("127.0.0.1", 0) is None
    assert build_engine_url("bad host", 8765) is None


def test_build_engine_url_scheme_follows_tls() -> None:
    """[api].tls_cert_file flips the same bind to https — the discovered URL must follow."""
    assert build_engine_url("127.0.0.1", 8765, tls=True) == "https://127.0.0.1:8765"
    assert build_engine_url("127.0.0.1", 8765, tls=False) == "http://127.0.0.1:8765"


def test_build_engine_url_brackets_a_bare_ipv6_literal() -> None:
    """`serve --host ::1` must not yield the unparseable "http://::1:8765"."""
    assert build_engine_url("::1", 8765) == "http://[::1]:8765"
    assert build_engine_url("[::1]", 8765) == "http://[::1]:8765"  # already bracketed
    assert is_local_engine(build_engine_url("::1", 8765) or "") is True


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://127.0.0.1:8765", True),
        ("http://localhost:8765", True),
        ("http://[::1]:8765", True),
        # A TLS-hardened loopback engine is STILL the local box: scheme is not locality.
        ("https://127.0.0.1:8765", True),
        ("https://localhost:8765", True),
        ("http://10.0.0.5:8765", False),  # remote → monitor-only
        ("https://10.0.0.5:8765", False),  # remote, TLS or not → monitor-only
        ("http://engine.example.com", False),
        ("file:///c:/nope", False),  # not an engine URL at all
        ("", False),
    ],
)
def test_is_local_engine(url: str, local: bool) -> None:
    assert is_local_engine(url) is local


@pytest.mark.parametrize(
    ("url", "tls"),
    [
        ("https://127.0.0.1:8765", True),
        ("http://127.0.0.1:8765", False),
        ("", False),
    ],
)
def test_is_tls_url(url: str, tls: bool) -> None:
    assert is_tls_url(url) is tls


def test_compose_defaults() -> None:
    cfg = compose_config(None, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL
    assert cfg.service_name == DEFAULT_SERVICE_NAME
    assert cfg.repo_path is None
    assert cfg.monitor_only is False


def test_compose_registry_hints() -> None:
    reg = ServiceRegistryInfo(
        app_directory="C:\\Users\\me\\Code\\MessageFoundry",
        app_parameters="serve --config C:\\cfg --host 127.0.0.1 --port 9100 --env prod",
        app_stdout="C:\\ProgramData\\MessageFoundry\\logs\\service.out.log",
    )
    cfg = compose_config(None, reg)
    # https: with no engine settings to say otherwise, the engine runs on its defaults, which mint.
    assert cfg.engine_url == "https://127.0.0.1:9100"
    assert cfg.repo_path == "C:\\Users\\me\\Code\\MessageFoundry"
    assert cfg.log_path is not None and cfg.log_path.endswith("service.out.log")


def test_compose_toml_overrides_registry() -> None:
    reg = ServiceRegistryInfo(app_parameters="serve --host 127.0.0.1 --port 9100")
    toml_data: dict[str, object] = {
        "engine_url": "http://127.0.0.1:8765/",  # trailing slash normalized away
        "service_name": "MEFOR_Prod",
        "repo_path": "D:\\repo",
        "poll_seconds": 10,
    }
    cfg = compose_config(toml_data, reg)
    assert cfg.engine_url == "http://127.0.0.1:8765"  # toml wins, slash stripped
    assert cfg.service_name == "MEFOR_Prod"
    assert cfg.repo_path == "D:\\repo"
    assert cfg.poll_seconds == 10.0


def test_compose_rejects_unsafe_service_name() -> None:
    cfg = compose_config({"service_name": "evil & name | rm"}, None)
    assert cfg.service_name == DEFAULT_SERVICE_NAME


def test_compose_rejects_hostile_path_hints() -> None:
    reg = ServiceRegistryInfo(app_directory="C:\\ok\\path\x00malicious")
    assert compose_config(None, reg).repo_path is None
    toml_data: dict[str, object] = {"repo_path": "x" * 5000}
    assert compose_config(toml_data, None).repo_path is None


def test_compose_poll_seconds_bool_rejected_and_clamped() -> None:
    # bool is an int subclass — must not be accepted as a poll interval.
    assert compose_config({"poll_seconds": True}, None).poll_seconds == 5.0
    assert compose_config({"poll_seconds": 0.1}, None).poll_seconds == 1.0  # clamp floor
    assert compose_config({"poll_seconds": 999999}, None).poll_seconds == 3600.0  # clamp ceiling


def test_monitor_only_keys_on_locality_not_scheme() -> None:
    """The regression this fixes: TLS on the loopback bind used to grey out Start/Stop/Restart."""
    assert compose_config({"engine_url": "http://127.0.0.1:8765"}, None).monitor_only is False
    assert compose_config({"engine_url": "https://127.0.0.1:8765"}, None).monitor_only is False
    assert compose_config({"engine_url": "https://localhost:8765"}, None).monitor_only is False
    # Remote stays monitor-only regardless of scheme — service control needs the local box.
    assert compose_config({"engine_url": "http://10.0.0.9:8765"}, None).monitor_only is True
    assert compose_config({"engine_url": "https://10.0.0.9:8765"}, None).monitor_only is True


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ("serve --service-config C:\\svc\\mefor.toml", "C:\\svc\\mefor.toml"),
        ("serve --service-config=mefor.toml --env prod", "mefor.toml"),
        ("serve --config C:\\cfg --host 127.0.0.1", None),
        ("serve --service-config", None),  # trailing flag, no value
        ("serve --service-config bad\x00path", None),  # NUL-bearing → rejected
        # BACKLOG #1565, the filed case: a quoted path with a space.
        (
            'serve --service-config "C:\\Program Files\\MF\\mefor.toml" --env prod',
            "C:\\Program Files\\MF\\mefor.toml",
        ),
        # ...and the same quoting with no space in the path, which failed identically.
        ('serve --service-config "C:\\svc\\mefor.toml"', "C:\\svc\\mefor.toml"),
        # The equals form with a quoted value. The unquoted equals form already worked; the '='
        # split is unchanged and now runs on a dequoted token.
        ('serve --service-config="C:\\P F\\mefor.toml"', "C:\\P F\\mefor.toml"),
        # Malformed quoting yields the path rather than nothing -- fail-soft, as before.
        ('serve --service-config "C:\\svc\\mefor.toml', "C:\\svc\\mefor.toml"),
        # NOT COVERED, and correctly so: apostrophes are not a Windows quoting form, so
        # CommandLineToArgvW keeps them and the path really is named with them.
        ("serve --service-config 'C:\\svc\\x.toml'", "'C:\\svc\\x.toml'"),
    ],
)
def test_parse_service_config_arg(args: str, expected: str | None) -> None:
    assert parse_service_config_arg(args) == expected


@pytest.mark.parametrize(
    ("data", "tls"),
    [
        # an operator chain always wins -- ensure_api_tls_material returns it unchanged
        ({"api": {"tls_cert_file": "C:\\certs\\engine.pem"}}, True),
        # THE SHIPPED DEFAULT: no chain and no declared proxy, so the engine MINTS and serves https.
        # All four of these read as "no cert" and every one of them used to answer False. That is
        # the BACKLOG #1126 defect, and ADR 0172 predicted it in writing: the tray composed an http
        # URL against an https listener and would render a running engine as WEDGED.
        ({"api": {"tls_cert_file": ""}}, True),
        ({"api": {"tls_cert_file": "   "}}, True),
        ({"api": {"tls_cert_file": None}}, True),
        ({"api": {"host": "127.0.0.1"}}, True),
        # a DECLARED upstream terminator is the ONE topology that mints nothing (api/tls.py)
        ({"api": {"tls_terminated_upstream": True}}, False),
        # ... and an operator cert set alongside it still serves https, because that branch returns
        # first. Ordering here is not cosmetic: get it backwards and the declared-proxy arm swallows
        # a configured chain.
        ({"api": {"tls_terminated_upstream": True, "tls_cert_file": "C:\\c.pem"}}, True),
        # only a literal True declares the topology; a string is not a TOML boolean
        ({"api": {"tls_terminated_upstream": False}}, True),
        ({"api": {"tls_terminated_upstream": "yes"}}, True),
        # no readable settings at all -- the engine then runs on its own defaults, which mint
        ({"api": "not-a-table"}, True),
        ({}, True),
        (None, True),
    ],
)
def test_engine_serves_https(data: dict[str, object] | None, tls: bool) -> None:
    assert engine_serves_https(data) is tls


def test_service_toml_path_resolution(tmp_path: Path) -> None:
    # tmp_path (not a literal) so "absolute" means the same thing on the Windows and Linux legs.
    repo = tmp_path / "repo"
    elsewhere = tmp_path / "svc" / "x.toml"

    # Explicit absolute --service-config wins.
    reg = ServiceRegistryInfo(
        app_directory=str(repo), app_parameters=f"serve --service-config {elsewhere}"
    )
    assert service_toml_path(reg) == elsewhere
    # A relative one resolves against AppDirectory (a service's cwd), like serve itself.
    reg = ServiceRegistryInfo(
        app_directory=str(repo), app_parameters="serve --service-config x.toml"
    )
    assert service_toml_path(reg) == repo / "x.toml"
    # No flag → the engine's own default filename under AppDirectory.
    reg = ServiceRegistryInfo(app_directory=str(repo), app_parameters="serve --host 127.0.0.1")
    assert service_toml_path(reg) == repo / "messagefoundry.toml"
    # A quoted absolute path with a space resolves to that same file (BACKLOG #1565). Before the
    # tokenizer this became '"<tmp>/svc' -- a relative-looking fragment joined onto AppDirectory.
    spaced = tmp_path / "svc dir" / "x.toml"
    reg = ServiceRegistryInfo(
        app_directory=str(repo), app_parameters=f'serve --service-config "{spaced}"'
    )
    assert service_toml_path(reg) == spaced
    # Nothing to anchor on → nothing to read.
    assert service_toml_path(ServiceRegistryInfo(app_parameters="serve")) is None
    assert service_toml_path(None) is None


class _FakeReader:
    def __init__(self, info: ServiceRegistryInfo | None) -> None:
        self._info = info
        self.asked: list[str] = []

    def read_service_params(self, service_name: str) -> ServiceRegistryInfo | None:
        self.asked.append(service_name)
        return self._info


def test_load_config_reads_toml_and_registry(tmp_path: Path) -> None:
    (tmp_path / "tray.toml").write_text(
        'service_name = "MEFOR_Prod"\npoll_seconds = 7\n', encoding="utf-8"
    )
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory="C:\\repo",
            app_parameters="serve --host 127.0.0.1 --port 9200",
        )
    )
    cfg = load_config(tmp_path, reader)
    # The registry was queried with the TOML-resolved service name.
    assert reader.asked == ["MEFOR_Prod"]
    assert cfg.service_name == "MEFOR_Prod"
    assert cfg.poll_seconds == 7.0
    # The host and port come from the registry hint; the SCHEME comes from the engine's own
    # settings, and there are none here -- so the engine runs on its defaults, which mint (ADR 0172).
    assert cfg.engine_url == "https://127.0.0.1:9200"
    assert cfg.repo_path == "C:\\repo"


def test_load_config_discovers_an_https_engine_from_the_service_toml(tmp_path: Path) -> None:
    """NSSM discovery must be able to yield https — there is no `serve` TLS flag to sniff, so the
    scheme comes from [api].tls_cert_file in the engine's own settings TOML."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text(
        '[api]\nhost = "127.0.0.1"\nport = 8765\ntls_cert_file = "C:\\\\certs\\\\engine.pem"\n',
        encoding="utf-8",
    )
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo),
            app_parameters="serve --config C:\\cfg --host 127.0.0.1 --port 8765 --env prod",
        )
    )
    cfg = load_config(tmp_path, reader)
    assert cfg.engine_url == "https://127.0.0.1:8765"
    # ...and a TLS engine on loopback stays fully managed.
    assert cfg.monitor_only is False


def test_load_config_a_certless_service_toml_now_discovers_https(tmp_path: Path) -> None:
    """The BACKLOG #1126 regression, at the load_config seam rather than the predicate.

    This case used to assert http, under the retired premise that no ``[api].tls_cert_file`` means
    a cleartext bind. Since ADR 0172 an engine with no chain and no declared proxy MINTS one and
    serves https, so the old expectation composed a URL that would probe an https listener over
    http and render a running engine as WEDGED.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "https://127.0.0.1:8765"


def test_load_config_a_declared_upstream_terminator_stays_http(tmp_path: Path) -> None:
    """The NEGATIVE control for the test above, and the one topology that is genuinely cleartext.

    Without it, the https assertions everywhere else would pass equally if the tray had simply been
    hardcoded to https. ``tls_terminated_upstream`` is the single arm where
    ``ensure_api_tls_material`` returns no material and the engine speaks plaintext to its proxy.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text(
        "[api]\ntls_terminated_upstream = true\n", encoding="utf-8"
    )
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:8765"


def test_load_config_finds_a_quoted_service_config_path_with_a_space(tmp_path: Path) -> None:
    """BACKLOG #1565 end to end, on the one topology where losing the file changes the answer.

    A ``--service-config`` path with a space is quoted in ``AppParameters``, and ``str.split()``
    turned that into fragments, so the settings read as absent and the tray composed https. A
    deploying site that had declared ``tls_terminated_upstream`` would then have probed https
    against an engine deliberately speaking plaintext to its proxy, and rendered a running engine
    as WEDGED.

    The shipped ``scripts/service/install-service.ps1`` writes no ``--service-config`` at all, so
    this is the hand-edited posture rather than the stock one. Its quoted ``--config``/``--db``
    values fragmented too, but harmlessly: neither flag is in ``wanted``, and ``--host``/``--port``
    sat outside the quotes, so a stock install parsed the same before and after this change.
    """
    repo = tmp_path / "Program Files" / "MessageFoundry"
    repo.mkdir(parents=True)
    svc = repo / "svc settings.toml"
    svc.write_text("[api]\ntls_terminated_upstream = true\n", encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo),
            app_parameters=f'serve --host 127.0.0.1 --port 8765 --service-config "{svc}"',
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:8765"


def test_load_config_unreadable_service_toml_is_fail_soft(tmp_path: Path) -> None:
    """The service TOML is operator data reached via an untrusted registry hint: a missing or
    malformed file must never raise into the tray's startup.

    Fail-soft is about not raising, and that is unchanged. What changed is the DEGRADED ANSWER: an
    engine whose settings the tray cannot read is running on the engine's own defaults, and those
    mint (ADR 0172), so the quiet fallback is https rather than http.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text("this is = = not toml", encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "https://127.0.0.1:8765"
    # Absent entirely (no AppDirectory to anchor on) is equally quiet.
    bare = _FakeReader(ServiceRegistryInfo(app_parameters="serve --host 127.0.0.1 --port 8765"))
    assert load_config(tmp_path, bare).engine_url == "https://127.0.0.1:8765"


def test_load_config_tray_toml_engine_url_beats_the_tls_hint(tmp_path: Path) -> None:
    """An explicit engine_url carries its own scheme and must not be scheme-rewritten."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "messagefoundry.toml").write_text('[api]\ntls_cert_file = "c.pem"\n', encoding="utf-8")
    (tmp_path / "tray.toml").write_text("engine_url = 'http://127.0.0.1:9999'\n", encoding="utf-8")
    reader = _FakeReader(
        ServiceRegistryInfo(
            app_directory=str(repo), app_parameters="serve --host 127.0.0.1 --port 8765"
        )
    )
    assert load_config(tmp_path, reader).engine_url == "http://127.0.0.1:9999"


def test_load_config_missing_file_uses_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL
    assert cfg.service_name == DEFAULT_SERVICE_NAME


def test_load_config_malformed_toml_falls_back(tmp_path: Path) -> None:
    (tmp_path / "tray.toml").write_text("this is = = not valid toml", encoding="utf-8")
    cfg = load_config(tmp_path, None)
    assert cfg.engine_url == DEFAULT_ENGINE_URL


def test_ensure_tray_toml_writes_template_then_is_idempotent(tmp_path: Path) -> None:
    from messagefoundry.tray.config import TRAY_TOML_TEMPLATE, ensure_tray_toml

    path = ensure_tray_toml(tmp_path)
    assert path == tmp_path / "tray.toml"
    written = path.read_text(encoding="utf-8")
    assert written == TRAY_TOML_TEMPLATE
    assert "repo_path" in written  # the key issue-2 asks about is documented
    # A written template is inert (all keys commented) → still resolves to defaults.
    assert load_config(tmp_path, None).engine_url == DEFAULT_ENGINE_URL
    # Idempotent: never clobbers an operator's edits.
    path.write_text("engine_url = 'http://x:9'\n", encoding="utf-8")
    ensure_tray_toml(tmp_path)
    assert path.read_text(encoding="utf-8") == "engine_url = 'http://x:9'\n"


# --- The minted-certificate pin (ADR 0172) --------------------------------------------------------


def test_default_engine_url_is_https() -> None:
    """A stock engine serves TLS (ADR 0172), so a plaintext default probes a socket that hangs up."""
    assert DEFAULT_ENGINE_URL == "https://127.0.0.1:8765"


# The AppParameters shape scripts/service/install-service.ps1 writes, which always has an absolute
# --db. Built from a real absolute path so Path.is_absolute() agrees on every OS the suite runs on.
def _installed(db: Path) -> str:
    return (
        f'serve --config "C:\\MF\\config" --db "{db}" '
        "--host 127.0.0.1 --port 8765 --log-level INFO --env prod"
    )


def _reg(params: str, app_directory: str | None) -> ServiceRegistryInfo:
    return ServiceRegistryInfo(app_directory=app_directory, app_parameters=params)


def test_generated_cert_path_follows_an_absolute_db(tmp_path: Path) -> None:
    db = tmp_path / "data" / "messagefoundry.db"
    got = generated_cert_path(None, _reg(_installed(db), str(tmp_path / "elsewhere")))
    assert got == str(tmp_path / "data" / "api-generated-cert.pem")


def test_generated_cert_path_resolves_a_relative_db_against_app_directory(tmp_path: Path) -> None:
    got = generated_cert_path(None, _reg("serve --db data/mf.db", str(tmp_path)))
    assert got == str(tmp_path / "data" / "api-generated-cert.pem")


def test_generated_cert_path_falls_back_to_store_path_then_the_default(tmp_path: Path) -> None:
    toml: dict[str, object] = {"store": {"path": "state/mf.db"}}
    assert generated_cert_path(toml, _reg("serve --port 8765", str(tmp_path))) == str(
        tmp_path / "state" / "api-generated-cert.pem"
    )
    # No --db and no [store].path: the engine's own default, messagefoundry.db, under AppDirectory.
    assert generated_cert_path(None, _reg("serve --port 8765", str(tmp_path))) == str(
        tmp_path / "api-generated-cert.pem"
    )


@pytest.mark.parametrize(
    "toml",
    [
        {"api": {"tls_cert_file": "C:\\certs\\engine.pem"}},  # operator chain: OS trust store
        {"api": {"tls_terminated_upstream": True}},  # plaintext to a proxy: nothing to pin
    ],
)
def test_generated_cert_path_is_none_when_the_engine_serves_no_minted_pair(
    toml: dict[str, object], tmp_path: Path
) -> None:
    assert generated_cert_path(toml, _reg(_installed(tmp_path / "mf.db"), str(tmp_path))) is None


def test_generated_cert_path_does_not_guess(tmp_path: Path) -> None:
    """No service entry, no working directory, or a project root the tray does not resolve."""
    base = str(tmp_path)
    assert generated_cert_path(None, None) is None
    assert generated_cert_path(None, _reg("serve --db mf.db", None)) is None
    assert generated_cert_path(None, _reg("serve --project-root estate --db mf.db", base)) is None
    rooted: dict[str, object] = {"environments": {"base_dir": "estate"}}
    assert generated_cert_path(rooted, _reg("serve --db mf.db", base)) is None
    # An ABSOLUTE --db is honoured as-is even under a root, exactly as serve honours it.
    db = tmp_path / "d" / "mf.db"
    assert generated_cert_path(None, _reg(f'serve --project-root estate --db "{db}"', base)) == str(
        tmp_path / "d" / "api-generated-cert.pem"
    )


def test_compose_an_explicit_engine_url_drops_the_derived_pin() -> None:
    """The derived pin belongs to the local service; an explicit URL may name another engine."""
    reg = _reg("serve --host 127.0.0.1 --port 8765", None)
    derived = compose_config(None, reg, engine_cacert="derived.pem")
    assert derived.engine_url == "https://127.0.0.1:8765"
    assert derived.engine_cacert == "derived.pem"
    explicit = compose_config({"engine_url": "https://127.0.0.1:9999"}, reg, engine_cacert="d.pem")
    assert explicit.engine_cacert is None


def test_compose_an_explicit_engine_cacert_wins(tmp_path: Path) -> None:
    mine = str(tmp_path / "mine.pem")
    toml: dict[str, object] = {"engine_cacert": mine}
    assert compose_config(toml, None, engine_cacert="derived.pem").engine_cacert == mine


def test_compose_a_relative_engine_cacert_is_ignored() -> None:
    """A relative pin would resolve against whatever directory the tray started in."""
    toml: dict[str, object] = {"engine_cacert": "mine.pem"}
    assert compose_config(toml, None, engine_cacert="derived.pem").engine_cacert == "derived.pem"


def test_a_blank_cert_path_is_classified_as_the_engine_classifies_it(tmp_path: Path) -> None:
    """The tray passes tls_cert_file raw, as the engine does, so a blank one reads as an operator
    chain on both sides and the tray derives no pin for a pair the engine would never mint."""
    toml: dict[str, object] = {"api": {"tls_cert_file": " "}}
    assert engine_serves_https(toml) is True
    assert generated_cert_path(toml, _reg(_installed(tmp_path / "mf.db"), str(tmp_path))) is None


def test_load_config_pins_the_minted_cert_of_an_installed_service(tmp_path: Path) -> None:
    """End to end over the shipped install shape: the scheme AND the trust anchor, both derived."""
    data = tmp_path / "data"
    reader = _FakeReader(_reg(_installed(data / "messagefoundry.db"), str(tmp_path)))
    cfg = load_config(tmp_path, reader)
    assert cfg.engine_url == "https://127.0.0.1:8765"
    assert cfg.engine_cacert == str(data / "api-generated-cert.pem")


def test_load_config_an_operator_chain_pins_nothing(tmp_path: Path) -> None:
    """The NEGATIVE control: https, but trusted through the OS store rather than a pin."""
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\ntls_cert_file = "engine.pem"\n', encoding="utf-8"
    )
    reader = _FakeReader(_reg(_installed(tmp_path / "messagefoundry.db"), str(tmp_path)))
    cfg = load_config(tmp_path, reader)
    assert cfg.engine_url == "https://127.0.0.1:8765"
    assert cfg.engine_cacert is None
