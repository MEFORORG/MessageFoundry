# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Support-bundle (#49) tests: the zip contents, the secret-free config summary, the status snapshot
built from the real models, and the log-tail redaction — with the hard rule that no raw message body
or secret reaches the bundle."""

from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path

import pytest

from messagefoundry import __version__
from messagefoundry.support import build_bundle, redact_log_line, redact_log_text
from messagefoundry.support.bundle import config_summary, status_snapshot
from messagefoundry.support.redact import REDACTION_PLACEHOLDER


def _members(zip_path: Path) -> dict[str, str]:
    with zipfile.ZipFile(zip_path) as zf:
        return {name: zf.read(name).decode("utf-8") for name in zf.namelist()}


def _provision_store(db: Path) -> None:
    """Create the SQLite store at ``db`` the way serve's first run does. The bundle reports on a store
    and no longer creates the one it is pointed at (BACKLOG #1780), so a test that wants DbInfo makes
    the store first."""
    from messagefoundry.store.base import open_store, sqlite_settings

    async def _make() -> None:
        store = await open_store(sqlite_settings(db), create=True, keyless_chain_refusal=None)
        await store.close()

    asyncio.run(_make())


def test_bundle_writes_expected_members(tmp_path: Path) -> None:
    out = tmp_path / "bundle.zip"
    result = build_bundle(out, config_dir=None, settings=None)
    assert Path(result.path) == out
    members = _members(out)
    assert "version.txt" in members
    assert "manifest.json" in members
    assert "status.json" in members
    assert "config-summary.json" in members
    # No app-log without settings/log_dir.
    assert "app-log.txt" not in members
    assert members["version.txt"].strip() == __version__


def test_bundle_version_and_manifest(tmp_path: Path) -> None:
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=None, now=1_700_000_000.0)
    members = _members(out)
    manifest = json.loads(members["manifest.json"])
    assert manifest["version"] == __version__
    assert manifest["generated_at"] == 1_700_000_000.0
    assert "phi_contract" in manifest
    assert "no raw message bodies" in manifest["phi_contract"]


def test_status_snapshot_uses_real_models() -> None:
    # No settings -> engine info from __version__, db None. Built from the REAL status models.
    snap = status_snapshot(None)
    assert snap["engine"]["version"] == __version__
    assert snap["engine"]["uptime_seconds"] == 0.0
    assert snap["db"] is None


def test_config_summary_counts_only_no_settings_values(tmp_path: Path) -> None:
    # A minimal valid config dir: one inbound + one outbound + a router + handler.
    cfg = tmp_path / "config"
    cfg.mkdir()
    secret_dir = "/srv/secret-internal-outdir"
    (cfg / "feed.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File\n"
        "inbound('IB_ACME_ADT', MLLP(port=2575), router='route')\n"
        f"outbound('OB_ACME_ADT', File(directory={secret_dir!r}))\n"
        "@router('route')\n"
        "def route(msg):\n"
        "    return ['handle']\n"
        "@handler('handle')\n"
        "def handle(msg):\n"
        "    return Send('OB_ACME_ADT', msg)\n",
        encoding="utf-8",
    )
    summary = config_summary(cfg)
    assert summary["loaded"] is True
    assert summary["counts"] == {"inbound": 1, "outbound": 1, "routers": 1, "handlers": 1}
    assert summary["inbound"] == [{"name": "IB_ACME_ADT", "type": "mllp"}]
    # The HARD RULE: no settings value (host/port/path) leaks into the summary.
    blob = json.dumps(summary)
    assert secret_dir not in blob
    assert "2575" not in blob


def test_config_summary_broken_config_reports_error(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "bad.py").write_text("this is not valid python !!!\n", encoding="utf-8")
    summary = config_summary(cfg)
    assert summary["loaded"] is False
    assert "error" in summary


def test_config_summary_reports_a_connection_less_config_as_loaded(tmp_path: Path) -> None:
    """A config that declares no connection LOADED — the bundle must not call that a load failure.

    The bundle reports a graph, it does not gate one, so the #1648 empty-graph refusal is dropped
    here: reporting ``loaded: False`` would send support looking for an import error that does not
    exist, while the emptiness is already stated, and stated better, by the zero counts.

    Falsified by dropping ``allow_empty=True`` from ``config_summary``'s ``load_config``."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "helpers.py").write_text(
        'from messagefoundry import router\n\n@router("r")\ndef route(msg):\n    return []\n',
        encoding="utf-8",
    )
    summary = config_summary(cfg)
    assert summary["loaded"] is True
    assert "error" not in summary
    assert summary["counts"]["inbound"] == 0 and summary["counts"]["outbound"] == 0


# --- BACKLOG #1716: hold each log-tail sentinel clear of the passes that need no label -------------
#
# These four values were 32, 32, 28 and 25 characters of pure base64 alphabet, which ``_LONG_B64`` --
# the redactor's catch-everything backstop, which is nobody's named rule here -- reaches on its own.
# Measured at baf53b3ae by disabling each fixture's OWN patterns and re-running it: all four
# assertions still passed, so not one of them was evidence about the rule in its own name. Deleting
# ``_MEFOR_SECRET``, ``_BEARER`` or ``_MFB64`` outright would have left this file green.
#
# WHAT THE NEW SHAPES BUY, STATED EXACTLY, BECAUSE IT IS NOT FOUR OUT OF FOUR. ``_MFB64`` and, on the
# mefor-name line, ``_MEFOR_SECRET`` are now pinned ALONE: delete either and its assertion reds. The
# other two are pinned to a PAIR, because two rules legitimately reach one label -- ``_MEFOR_SECRET``
# + ``_KEY_MATERIAL`` on ``MEFOR_STORE_ENCRYPTION_KEY=``, ``_BEARER`` + ``_AUTH_SCHEME`` on an
# ``Authorization: Bearer`` line. Both of a pair must go before those leak, so deleting ``_BEARER``
# alone still leaves this file green. That is the #1183 defect shape NARROWED -- from "one backstop
# covers all four" to "one sibling covers one" -- and not eliminated.
#
# THE RESIDUE IS GRADED, JUST NOT HERE. ``tests/test_log_redaction_secret_domain.py`` declares a
# family's own patterns and disables exactly those, which is the instrument that reaches a sibling
# pair. It is left there rather than reproduced here because it grades the redactor IN ISOLATION,
# while this file's whole value is the same redactor reached END TO END through ``build_bundle``. A
# sentinel is published on one surface only (see the .gitleaks.toml blocks), so the two files hold
# different needles on purpose.
#
# The sentinels copy the #1183 shape: a hyphen AND an underscore, or -- for a base64 body, which can
# carry neither -- short enough to miss the 24-character sweep.
#
# Invented here. No real credential.
_STORE_KEY_SENTINEL = "ek-Bndl_Enc-41"
_BEARER_SENTINEL = "sk-Bndl_Bear-42"
_MFB64_SENTINEL = "SGVsbG9Xb3JsZA=="
_MEFOR_NAME_SENTINEL = "dek-Bndl_Wrp-12"

# The fixture TEXT is hoisted beside the sentinels so the control below can assert over the same
# bytes the tests feed in. BOTH label-free passes are properties of the LINE, not of the constant:
# ``_LONG_B64`` spans whatever base64-alphabet characters NEIGHBOUR a sentinel, and ``_redact_phi``
# reaches a capitalized name run or a date run anywhere on the line, so a value that is clear on its
# own can still be swept where it sits. Checking a constant alone would agree with the real property
# only by luck -- today the labels happen to supply a "_", a ":" or a space that breaks every run,
# and to carry no name or date run the PHI pass would extend over the value.
_LEAKY_LOG = (
    "2026-06-27 INFO routing message\n"
    "PID|1||123456^^^MR||DOE^JANE^Q||19800101|F\n"
    f"MEFOR_STORE_ENCRYPTION_KEY={_STORE_KEY_SENTINEL}\n"
    f"Authorization: Bearer {_BEARER_SENTINEL}\n"
    f"blob mfb64:v1:{_MFB64_SENTINEL}\n"
)
_MEFOR_NAME_LINE = f"env MEFOR_STORE_VAULT_WRAPPED_DEK={_MEFOR_NAME_SENTINEL} loaded"


def _line_holding(sentinel: str) -> str:
    """The fixture line a sentinel sits in -- the bytes a redaction pass actually sees."""
    for line in (*_LEAKY_LOG.splitlines(), _MEFOR_NAME_LINE):
        if sentinel in line:
            return line
    raise AssertionError(f"{sentinel!r} sits in no fixture line above")


#: Each sentinel beside its own line, derived rather than written out so the two cannot drift.
_SENTINEL_LINES = tuple(
    (sentinel, _line_holding(sentinel))
    for sentinel in (
        _STORE_KEY_SENTINEL,
        _BEARER_SENTINEL,
        _MFB64_SENTINEL,
        _MEFOR_NAME_SENTINEL,
    )
)


def test_no_bundle_log_sentinel_is_reachable_by_a_label_free_pass() -> None:
    """The control that makes the two redaction tests below mean something (BACKLOG #1716).

    A pass that reaches a VALUE without matching a label first redacts a sentinel whatever the
    sentinel's own named rule does, so an assertion resting on one proves nothing.
    ``redact_log_line`` runs AT LEAST two of them and both are checked here: ``_LONG_B64``, which
    sweeps any run of 24+ base64 characters, and the shared engine PHI pass ``_redact_phi``, which
    reaches a capitalized name run or a date run with no label in sight. The PHI pass is read off the
    redactor module rather than imported by name, so swapping the chain's PHI implementation moves
    this control with it.

    Both passes are fed the fixture LINE rather than the bare constant, for the reason recorded
    above the fixtures: either can reach a value through the characters beside it, so a control that
    only ever sees the constant certifies a property adjacent to the one that matters.

    ``_LONG_B64`` is asked twice, because the chain runs it LAST -- after ``_redact_phi`` has already
    rewritten the line. As-written answers "was the fixture authored over the sweep"; post-PHI
    answers "does the sweep reach the sentinel where it actually runs". The two agree today (the PHI
    pass only ever substitutes a bracketed placeholder, which breaks a base64 run rather than
    joining one), and a fixture that made them disagree is exactly the case worth a red.
    """
    from messagefoundry.support import redact as redact_mod

    # Read off the module's namespace, not written as an attribute access: `_redact_phi` is an
    # import ALIAS in that module and not re-exported, so strict mypy rejects `redact_mod._redact_phi`
    # with "does not explicitly export attribute" (and ruff's B009 rejects the `getattr` spelling).
    # Reading it off the chain module is the property under test -- swap the chain's PHI
    # implementation and this control moves with it -- so the read stays.
    redact_phi = vars(redact_mod)["_redact_phi"]

    for what, text in (("the leaky log", _LEAKY_LOG), ("the mefor-name line", _MEFOR_NAME_LINE)):
        assert not redact_mod._LONG_B64.search(text), (
            f"{what} carries a 24+ base64 run, so the backstop covers it and a green on the "
            "fixture using it would prove nothing about the rule it is named for -- give the value "
            "a hyphen and an underscore, and check the characters NEIGHBOURING it"
        )

    for sentinel, line in _SENTINEL_LINES:
        after_phi: str = redact_phi(line)
        assert sentinel in after_phi, (
            f"{sentinel!r} is reachable by the shared PHI pass WHERE IT SITS, in {line!r}. That "
            "pass needs no credential label, so the fixture using it would stay green with the "
            "named rule deleted -- keep a capitalized word run and an 8-digit date run away from "
            "the value, not merely out of it"
        )
        assert not redact_mod._LONG_B64.search(after_phi), (
            f"the PHI pass leaves {line!r} as {after_phi!r}, which carries a 24+ base64 run, so the "
            "backstop reaches the sentinel at the point in the chain where it actually runs"
        )


def test_log_tail_redacted_no_phi_no_secret(tmp_path: Path) -> None:
    # Build a fake settings object pointing at a log dir holding a line with PHI + a secret.
    from messagefoundry.config.settings import load_settings

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text(_LEAKY_LOG, encoding="utf-8")

    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[logging]\nlog_dir = "{log_dir.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)
    members = _members(out)
    assert "app-log.txt" in members
    tail = members["app-log.txt"]
    # LIVENESS FIRST, because every assertion below is "value absent" and a line that never reached
    # the tail -- dropped, truncated, or cut by a tail-length change -- satisfies those exactly as
    # well as a working redactor does. Each fixture line is pinned by a token of its own that
    # survives redaction. Measured on this tree: the tail is one line per fixture line.
    for marker in (
        "INFO routing message",
        "PID|",
        "MEFOR_STORE_ENCRYPTION_KEY",
        "Authorization",
        "blob ",
    ):
        assert marker in tail, (
            f"{marker!r} never reached the bundle tail, so the assertions below would pass on the "
            "line being ABSENT rather than on the redactor having worked"
        )
    # PHI patient name + MRN must be gone (HL7 PID segment collapsed) -- the shared engine PHI pass
    # earns both of these: with it stubbed out, both values survive the whole chain verbatim.
    assert "DOE^JANE" not in tail
    assert "123456" not in tail
    # The secret VALUE is gone (the var NAME may remain so a reviewer sees which leaked). TWO rules
    # reach this label -- ``_MEFOR_SECRET`` on the MEFOR_ prefix, ``_KEY_MATERIAL`` on the
    # ``encryption_key`` tail -- which is the pair the domain file's ``mefor_env_value`` family
    # declares for the same reason.
    assert _STORE_KEY_SENTINEL not in tail
    # The bearer token value is gone: ``_BEARER`` on the header label, ``_AUTH_SCHEME`` on the bare
    # scheme word. Disabling both makes it leak; disabling either alone does not.
    assert _BEARER_SENTINEL not in tail
    # The embedded base64 body is gone. ``_MFB64`` is now the ONLY rule that reaches it -- the old
    # 28-character blob was swept by ``_LONG_B64`` as well.
    assert _MFB64_SENTINEL not in tail
    assert REDACTION_PLACEHOLDER in tail


def test_redact_hl7_segment() -> None:
    line = "got PID|1||999^^^MR||SMITH^JOHN||19700101|M and more"
    out = redact_log_line(line)
    assert "SMITH^JOHN" not in out
    assert "999" not in out
    assert out.startswith("got PID|")


def test_redact_mefor_secret_keeps_name() -> None:
    # BACKLOG #1716: a MEFOR_ name whose tail is NOT a credential word, so ``_MEFOR_SECRET`` -- the
    # rule this test is named for -- is the only one that reaches it. The previous fixture used
    # ``MEFOR_API_TOKEN``, which ``_BEARER`` also covers through its ``token`` alternate, with a
    # 25-character alphanumeric value the backstop covered on top: two accidental covers under a
    # name claiming to test a third rule.
    out = redact_log_line(_MEFOR_NAME_LINE)
    assert _MEFOR_NAME_SENTINEL not in out
    assert "MEFOR_STORE_VAULT_WRAPPED_DEK" in out  # the NAME is preserved for triage


def test_redact_text_preserves_line_count() -> None:
    text = "line one\nPID|1||x^^^MR||A^B||19700101|M\nline three"
    out = redact_log_text(text)
    assert len(out.splitlines()) == 3


def test_redact_plain_line_unchanged() -> None:
    # A short, ordinary log line with no secrets/PHI is left intact.
    line = "2026-06-27 INFO engine started on port 8765"
    assert redact_log_line(line) == line


def test_bundle_status_with_settings_db(tmp_path: Path) -> None:
    from messagefoundry.config.settings import load_settings

    db = tmp_path / "store.db"
    _provision_store(db)
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[store]\npath = "{db.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)
    members = _members(out)
    status = json.loads(members["status.json"])
    assert status["engine"]["version"] == __version__
    # DbInfo from the real model, populated from the opened store.
    assert status["db"] is not None
    assert status["db"]["journal_mode"]


# --- DELTA-05: the bundle must not disclose the store host / database name --------------------------


def test_redact_store_path_sqlite_keeps_basename_only() -> None:
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.support.bundle import _redact_store_path

    # A directory can carry a username or deployment path — drop it, keep just the file name.
    assert _redact_store_path("C:/deploy/scott/messagefoundry.db", StoreBackend.SQLITE) == (
        "messagefoundry.db"
    )


def test_redact_store_path_server_backends_hide_host_and_database() -> None:
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.support.bundle import _redact_store_path

    # sqlserver.py / postgres.py set path = "<server>/<database>"; that must never reach the bundle.
    leaky = "sql01.internal.example/MEFOR_PROD"
    assert _redact_store_path(leaky, StoreBackend.SQLSERVER) == "<sqlserver>"
    assert _redact_store_path(leaky, StoreBackend.POSTGRES) == "<postgres>"
    for backend in (StoreBackend.SQLSERVER, StoreBackend.POSTGRES):
        out = _redact_store_path(leaky, backend)
        assert "sql01.internal.example" not in out
        assert "MEFOR_PROD" not in out


def test_bundle_sqlite_status_path_is_basename_only(tmp_path: Path) -> None:
    from messagefoundry.config.settings import load_settings

    db = tmp_path / "secret-deploy-dir" / "store.db"
    db.parent.mkdir()
    _provision_store(db)
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[store]\npath = "{db.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)
    status = json.loads(_members(out)["status.json"])
    # The deployment directory (which can carry a username/host) is dropped: basename only.
    assert status["db"]["path"] == "store.db"
    assert "secret-deploy-dir" not in json.dumps(status)


# --- DELTA-07: the log redactor matches the engine redactor's PHI coverage --------------------------


def test_redact_catches_non_allowlisted_hl7_segment() -> None:
    # A segment id outside the old fixed allowlist (ZAL/IN2/RXA/...) must now still be scrubbed.
    out = redact_log_line("ZAL|1||SMITH^JOHN^Q||19700101 trailing")
    assert "SMITH^JOHN" not in out
    assert out.startswith("ZAL|")


def test_redact_catches_free_text_name_and_dob_in_body() -> None:
    # Delimiter-free PHI: a multi-token name + a DOB embedded in the message body are both redacted,
    # while the leading log timestamp (not a DOB) is preserved.
    out = redact_log_line("2026-06-27 ERROR patient DOE JANE dob 1980-05-05 not found")
    assert "DOE JANE" not in out
    assert "1980-05-05" not in out
    assert out.startswith("2026-06-27")


def test_redact_preserves_leading_timestamp() -> None:
    line = "2026-06-27 12:00:00 INFO engine started"
    assert redact_log_line(line).startswith("2026-06-27 12:00:00")


# --- BACKLOG #1571: no caught exception's MESSAGE reaches any bundle member -------------------------
#
# The bundle is by definition handed OUTSIDE the environment, and the summaries wrap exceptions raised
# by arbitrary config modules, the store driver and the filesystem — so their text is deployment- and
# attacker-shaped, and can carry a DSN password, a bearer token, a host or a message fragment. Each
# test below drives ONE failure branch with a synthetic payload and then reads back EVERY archive
# member, the manifest included: a test that checks only the member it expects to be dirty cannot tell
# you the value landed somewhere else.
#
# Every value here is invented. No real credential and no real PHI.

#: One payload per branch, so a hit names the branch that leaked it. Credential-shaped and, where the
#: branch wraps arbitrary module text, carrying a synthetic patient identifier too.
_CFG_WIRING_PAYLOAD = "Server=sql01.invalid;Uid=mefor;Pwd=Wq7Zn2Kb9xLm;"
_CFG_GENERIC_PAYLOAD = "Bearer synth0123456789abcdef PID|1||123456^^^MR||DOE^JANE^Q||19800101|F"
_DB_PAYLOAD = "postgresql://mefor:Tr9Vb4Nm8Qz@db01.invalid:5432/MEFOR_PROD"
#: These two must stay legal path components — they are injected as a directory and a file NAME, which
#: the shipped branches interpolate alongside the exception text.
_LOG_DIR_PAYLOAD = "logs-Uid-mefor-Pwd-Hs5Yt3Wc1Rk"
_LOG_FILE_PAYLOAD = "engine-Pwd-Jd6Fp8Lq4Vn"

#: The members that must exist for an absence assertion over the zip to mean anything. Without this a
#: bundle that wrote nothing would pass every "the payload is absent" check vacuously.
_CORE_MEMBERS = ("manifest.json", "version.txt", "status.json", "config-summary.json")


def _assert_no_member_carries(zip_path: Path, *needles: str) -> dict[str, str]:
    """Read EVERY member back and assert none of ``needles`` appears in any of them."""
    members = _members(zip_path)
    for name in _CORE_MEMBERS:
        assert name in members, f"bundle is missing {name!r}, so the absence check would be vacuous"
    for name, text in sorted(members.items()):
        for needle in needles:
            assert needle not in text, f"{needle!r} reached bundle member {name!r}"
    return members


def test_config_summary_wiring_error_drops_the_exception_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sink (b): the ``WiringError`` arm. A config module can raise with anything in the string."""
    from messagefoundry.config import wiring

    # **_: config_summary passes allow_empty= (BACKLOG #1648); a stub that refused the keyword
    # would raise TypeError and land in the CATCH-ALL arm, making this test assert CFG-002 while
    # claiming to cover CFG-001.
    def boom(_config_dir: object, **_: object) -> object:
        raise wiring.WiringError(_CFG_WIRING_PAYLOAD)

    monkeypatch.setattr(wiring, "load_config", boom)
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=tmp_path, settings=None)

    members = _assert_no_member_carries(out, _CFG_WIRING_PAYLOAD, "Wq7Zn2Kb9xLm", "sql01.invalid")
    summary = json.loads(members["config-summary.json"])
    assert summary["loaded"] is False
    # A fixed diagnostic code plus the exception TYPE — bounded, and enough to triage against.
    assert summary["error"] == "MF-BUNDLE-CFG-001 WiringError"


def test_config_summary_unexpected_error_drops_the_exception_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sink (a): the catch-all arm, which wraps whatever an arbitrary config module raised."""
    from messagefoundry.config import wiring

    def boom(_config_dir: object, **_: object) -> object:
        raise RuntimeError(_CFG_GENERIC_PAYLOAD)

    monkeypatch.setattr(wiring, "load_config", boom)
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=tmp_path, settings=None)

    members = _assert_no_member_carries(
        out, _CFG_GENERIC_PAYLOAD, "synth0123456789abcdef", "DOE^JANE", "123456"
    )
    summary = json.loads(members["config-summary.json"])
    assert summary["loaded"] is False
    assert summary["error"] == "MF-BUNDLE-CFG-002 RuntimeError"


def test_status_snapshot_db_failure_drops_the_exception_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sink (c): a store that will not open. A driver error routinely quotes the whole DSN."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.support import bundle as bundle_mod

    async def boom(_settings: object) -> object:
        raise RuntimeError(_DB_PAYLOAD)

    monkeypatch.setattr(bundle_mod, "_db_info", boom)
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[store]\npath = "{(tmp_path / "store.db").as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)

    members = _assert_no_member_carries(out, _DB_PAYLOAD, "Tr9Vb4Nm8Qz", "db01.invalid")
    status = json.loads(members["status.json"])
    assert status["db"] is None
    assert status["db_error"] == "MF-BUNDLE-DB-001 RuntimeError"


def test_log_tail_unlistable_dir_drops_the_path_and_the_exception_message(tmp_path: Path) -> None:
    """Sink (d), first branch: ``iterdir`` failed. The shipped branch returned BEFORE the redactor, so
    this text reached ``app-log.txt`` — the one member the manifest claims is redacted."""
    from messagefoundry.config.settings import load_settings

    missing = tmp_path / _LOG_DIR_PAYLOAD  # never created: iterdir raises, quoting the path
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[logging]\nlog_dir = "{missing.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)

    members = _assert_no_member_carries(out, _LOG_DIR_PAYLOAD, "Hs5Yt3Wc1Rk", str(missing))
    # Exact equality, so nothing else can ride along in the member.
    assert members["app-log.txt"] == "MF-BUNDLE-LOG-001 FileNotFoundError"


def test_log_tail_unreadable_file_drops_the_name_and_the_exception_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sink (d), second branch: the read failed. Both the file NAME and the error text were carried."""
    from messagefoundry.config.settings import load_settings

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    target = log_dir / f"{_LOG_FILE_PAYLOAD}.log"
    target.write_text("2026-06-27 INFO engine started\n", encoding="utf-8")

    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[logging]\nlog_dir = "{log_dir.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)

    # Patched only after the settings are loaded, and only for the target file, so nothing else in the
    # bundle path is disturbed by it.
    real_read_text = Path.read_text

    def boom(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == target.name:
            raise OSError(_DB_PAYLOAD)
        return real_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", boom)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)

    members = _assert_no_member_carries(
        out, _LOG_FILE_PAYLOAD, "Jd6Fp8Lq4Vn", _DB_PAYLOAD, "Tr9Vb4Nm8Qz"
    )
    assert members["app-log.txt"] == "MF-BUNDLE-LOG-002 OSError"
