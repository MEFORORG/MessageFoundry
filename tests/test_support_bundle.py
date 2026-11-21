# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Support-bundle (#49) tests: the zip contents, the secret-free config summary, the status snapshot
built from the real models, and the log-tail redaction — with the hard rule that no raw message body
or secret reaches the bundle."""

from __future__ import annotations

import asyncio
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any

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
    assert "no member reads a message body from the store" in manifest["phi_contract"]
    # BACKLOG #5385: a DEBUG log can hold a body the redaction does not read, so the contract names it.
    assert "DEBUG" in manifest["phi_contract"]
    assert "no raw message bodies" not in manifest["phi_contract"]


def test_manifest_phi_contract_does_not_claim_the_bundle_secret_free(tmp_path: Path) -> None:
    """BACKLOG #5385: the contract is machine-readable, so it must not open with an unqualified "no
    secrets" while the app-log tail it lists is only best-effort redacted. It names that residual."""
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=None)
    contract = json.loads(_members(out)["manifest.json"])["phi_contract"]
    assert "no secrets" not in contract.lower()
    assert "best-effort" in contract.lower()
    assert "username" in contract
    assert "at least" in contract  # a residual is a floor, not an enumeration (SDS-3.6)
    assert "not as secret-free or phi-free" in contract.lower()


def test_cli_help_and_build_docstring_state_the_phi_contract_residual(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5385 item 1: the support-bundle help and ``build_bundle``'s docstring must match the
    manifest's ``phi_contract``. The help named a username as the residual and omitted the
    DEBUG-logged body the contract names; the docstring said the function reads no "secret value"
    into the bundle, which the best-effort tail does not meet. The help is read from
    ``support-bundle --help``, what an operator runs, and each residual term it names must be one
    the contract names, so the two cannot drift apart unnoticed."""
    from messagefoundry.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(["support-bundle", "--help"])
    assert exc.value.code == 0
    # argparse wraps at a hyphen too, so a wrapped "single-token" is joined back before matching.
    help_text = re.sub(r"-\s+", "-", " ".join(capsys.readouterr().out.split())).lower()
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=None)
    contract = json.loads(_members(out)["manifest.json"])["phi_contract"].lower()
    for term in (
        "best-effort",
        "at least",
        "single-token identifier",
        "operator username",
        "debug",
        "message body",
        "not as secret-free or phi-free",
    ):
        assert term in help_text, term
        assert term in contract, term
    assert "phi_contract" in help_text

    doc = " ".join((build_bundle.__doc__ or "").split()).lower()
    assert "nor any secret value" not in doc
    assert "neither secret-free nor phi-free" in doc
    assert "phi_contract" in doc


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
    from messagefoundry.support import bundle as bundle_mod

    real_read = bundle_mod._read_log_file

    def boom(path: Path, listed: os.stat_result) -> str:
        if path.name == target.name:
            raise OSError(_DB_PAYLOAD)
        return real_read(path, listed)

    monkeypatch.setattr(bundle_mod, "_read_log_file", boom)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)

    members = _assert_no_member_carries(
        out, _LOG_FILE_PAYLOAD, "Jd6Fp8Lq4Vn", _DB_PAYLOAD, "Tr9Vb4Nm8Qz"
    )
    assert members["app-log.txt"] == "MF-BUNDLE-LOG-002 OSError"


# --- BACKLOG #5383, #5384: the log tail reads only a plain regular file, and only a positive count --


def _log_dir_settings(tmp_path: Path, log_dir: Path) -> object:
    from messagefoundry.config.settings import load_settings

    toml = tmp_path / "messagefoundry.toml"
    # The store is pinned under tmp_path, so the status snapshot never opens one in the working
    # directory.
    store = (tmp_path / "absent.db").as_posix()
    toml.write_text(
        f'[logging]\nlog_dir = "{log_dir.as_posix()}"\n[store]\npath = "{store}"\n',
        encoding="utf-8",
    )
    return load_settings(config_path=toml)


def _tail_member(tmp_path: Path, log_dir: Path, **kwargs: object) -> str | None:
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=_log_dir_settings(tmp_path, log_dir), **kwargs)  # type: ignore[arg-type]
    return _members(out).get("app-log.txt")


def test_log_tail_passes_over_a_symlink_to_a_file_outside_log_dir(tmp_path: Path) -> None:
    """A link with a log suffix, newer than the real log, used to be followed: the outside file's
    text was copied into ``app-log.txt`` (BACKLOG #5383)."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    real = log_dir / "engine.log"
    real.write_text("2026-06-27 INFO engine started\n", encoding="utf-8")
    outside = tmp_path / "outside-Kz7Wq2Lp9Xr.txt"
    outside.write_text("OUTSIDE-Kz7Wq2Lp9Xr\n", encoding="utf-8")
    link = log_dir / "zz-newest.log"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("this platform or account cannot create a symbolic link")
    os.utime(real, (1_000_000, 1_000_000))  # older than the link, so the link sorts newest

    tail = _tail_member(tmp_path, log_dir)
    assert tail is not None
    assert "Kz7Wq2Lp9Xr" not in tail
    assert "engine started" in tail


def test_log_tail_passes_over_a_directory_with_a_log_suffix(tmp_path: Path) -> None:
    """Kept by the new listing as the old ``is_file`` filter kept it."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "archive.log").mkdir()
    assert _tail_member(tmp_path, log_dir) is None


def test_log_tail_passes_over_a_hard_link_to_a_file_outside_log_dir(tmp_path: Path) -> None:
    """A second hard link is a regular file to every check but the link count, and the listing
    and the opened file agree on its id, so the count is what refuses it (BACKLOG #5383)."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    real = log_dir / "engine.log"
    real.write_text("2026-06-27 INFO engine started\n", encoding="utf-8")
    os.utime(real, (1_000_000, 1_000_000))
    outside = tmp_path / "outside-Wb5Hs1Nq.txt"
    outside.write_text("OUTSIDE-Wb5Hs1Nq\n", encoding="utf-8")
    try:
        os.link(outside, log_dir / "zz-newest.log")
    except (OSError, NotImplementedError):
        pytest.skip("this file system cannot create a hard link")

    tail = _tail_member(tmp_path, log_dir)
    assert tail is not None
    assert "Wb5Hs1Nq" not in tail
    assert "engine started" in tail


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX only")
@pytest.mark.timeout(30)
def test_read_log_file_does_not_block_on_a_fifo_swapped_in_after_the_listing(
    tmp_path: Path,
) -> None:
    """The listing leaves a FIFO out, as the old ``is_file`` filter did; the race is a FIFO put at
    the listed name before the open, which would block a plain open until a writer appeared
    (BACKLOG #5383). ``O_NONBLOCK`` returns at once and the identity check refuses it."""
    from messagefoundry.support import bundle as bundle_mod

    log = tmp_path / "engine.log"
    log.write_text("first\n", encoding="utf-8")
    listed = os.lstat(log)
    log.unlink()
    os.mkfifo(log)
    with pytest.raises(bundle_mod._LogFileRefused):
        bundle_mod._read_log_file(log, listed)


def test_read_log_file_refuses_a_file_swapped_in_after_the_listing(tmp_path: Path) -> None:
    """The check after the open holds where no open flag does (Windows): a different file at the
    listed path is refused, as a link followed to another file would be."""
    from messagefoundry.support import bundle as bundle_mod

    log = tmp_path / "engine.log"
    log.write_text("first\n", encoding="utf-8")
    listed = os.lstat(log)
    other = tmp_path / "other.log"
    other.write_text("SWAPPED-Vn3Qx8Rt\n", encoding="utf-8")
    os.replace(other, log)
    with pytest.raises(bundle_mod._LogFileRefused):
        bundle_mod._read_log_file(log, listed)


def _stale_listing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, times: int) -> list[int]:
    """Make the first ``times`` listings carry another file's stat, as a swap or a rotation
    between listing and opening would. Returns the call counter."""
    from messagefoundry.support import bundle as bundle_mod

    real_candidates = bundle_mod._log_candidates
    calls = [0]

    def stale(directory: Path) -> list[tuple[Path, os.stat_result]]:
        calls[0] += 1
        found = real_candidates(directory)
        if calls[0] > times:
            return found
        decoy = tmp_path / "decoy.log"
        decoy.write_text("x\n", encoding="utf-8")
        return [(p, os.lstat(decoy)) for p, _st in found]

    monkeypatch.setattr(bundle_mod, "_log_candidates", stale)
    return calls


def test_log_tail_swapped_file_twice_reports_the_refusal_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("SWAPPED-Vn3Qx8Rt\n", encoding="utf-8")
    calls = _stale_listing(monkeypatch, tmp_path, times=2)
    assert _tail_member(tmp_path, log_dir) == "MF-BUNDLE-LOG-002 _LogFileRefused"
    assert calls[0] == 2


def test_log_tail_a_rotation_between_listing_and_opening_is_read_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("after rotation\n", encoding="utf-8")
    calls = _stale_listing(monkeypatch, tmp_path, times=1)
    assert _tail_member(tmp_path, log_dir) == "after rotation"
    assert calls[0] == 2


@pytest.mark.parametrize("lines", [0, -1, -400])
def test_log_tail_not_positive_omits_the_app_log(tmp_path: Path, lines: int) -> None:
    """``[-0:]`` is the whole list and ``[-(-1):]`` is all but the first line, so a count that is
    not positive used to carry most or all of the newest log (BACKLOG #5384)."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("one\ntwo\nthree\n", encoding="utf-8")
    assert _tail_member(tmp_path, log_dir, log_tail_lines=lines) is None
    assert _tail_member(tmp_path, log_dir, log_tail_lines=2) == "two\nthree"


def test_cli_refuses_a_negative_log_tail_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(["support-bundle", "--out", str(tmp_path / "b.zip"), "--log-tail-lines", "-5"])
    assert exc.value.code == 2
    assert "zero or more lines" in capsys.readouterr().err
    assert not (tmp_path / "b.zip").exists()


def test_log_tail_a_file_gone_between_listing_and_opening_is_listed_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rotation renames the live file away before it creates the new one; an open in that gap
    finds nothing, and the second listing reads the new file."""
    from messagefoundry.support import bundle as bundle_mod

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("after rotation\n", encoding="utf-8")
    real_read = bundle_mod._read_log_file
    calls = [0]

    def gone_once(path: Path, listed: os.stat_result) -> str:
        calls[0] += 1
        if calls[0] == 1:
            raise FileNotFoundError(path.name)
        return real_read(path, listed)

    monkeypatch.setattr(bundle_mod, "_read_log_file", gone_once)
    assert _tail_member(tmp_path, log_dir) == "after rotation"
    assert calls[0] == 2


def test_read_log_file_closes_the_descriptor_on_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.support import bundle as bundle_mod

    log = tmp_path / "engine.log"
    log.write_text("first\n", encoding="utf-8")
    listed = os.lstat(log)
    other = tmp_path / "other.log"
    other.write_text("second\n", encoding="utf-8")
    os.replace(other, log)
    opened: list[int] = []
    real_open = os.open

    real_close = os.close
    closed: list[int] = []

    def recording_open(*args: Any, **kwargs: Any) -> int:
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def recording_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "close", recording_close)
    with pytest.raises(bundle_mod._LogFileRefused):
        bundle_mod._read_log_file(log, listed)
    # The descriptor the read opened is the one it closed: compared by the values the two calls
    # saw, never by asking the OS about a number another open may have reused since.
    assert len(opened) == 1
    assert closed == opened


def test_read_log_file_refuses_a_directory_swapped_in(tmp_path: Path) -> None:
    """POSIX opens a directory read-only, and the check refuses it as not a regular file; Windows
    refuses the open itself."""
    from messagefoundry.support import bundle as bundle_mod

    log = tmp_path / "engine.log"
    log.write_text("first\n", encoding="utf-8")
    listed = os.lstat(log)
    log.unlink()
    log.mkdir()
    expected: type[OSError] = OSError if os.name == "nt" else bundle_mod._LogFileRefused
    with pytest.raises(expected):
        bundle_mod._read_log_file(log, listed)


# --- BACKLOG #5385: the log read is bounded, so a large log cannot exhaust memory and lose the zip --


def test_log_tail_reads_only_a_bounded_tail_of_a_large_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole file used to be read into memory, so a large enough log raised ``MemoryError``,
    which nothing catches, and no zip was written. Only the last ``_LOG_TAIL_MAX_BYTES`` bytes are
    read now; the line the bound cuts into is dropped."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 64)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    lines = [f"line-{n:04d} synthetic" for n in range(200)]
    (log_dir / "engine.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tail = _tail_member(tmp_path, log_dir)
    assert tail is not None
    got = tail.split("\n")
    assert len(tail.encode("utf-8")) <= 64, tail
    # Whole lines only, and the newest ones, in order.
    assert got == lines[-len(got) :], got
    assert got[-1] == "line-0199 synthetic"


def test_log_tail_bound_on_a_line_start_drops_no_whole_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bound that falls exactly on a line start keeps that line: only a cut line is dropped."""
    from messagefoundry.support import bundle as bundle_mod

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_bytes(b"aaaa\r\nbbbb\r\ncccc\r\n")
    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 12)
    assert _tail_member(tmp_path, log_dir) == "bbbb\ncccc"
    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 11)
    assert _tail_member(tmp_path, log_dir) == "cccc"


def test_read_log_file_never_asks_for_more_than_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read itself is bounded, not only the text kept: a read of the whole file is what ran
    out of memory."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log = tmp_path / "engine.log"
    log.write_bytes(b"x" * 10 + b"\n" + b"y" * 1000 + b"\nlast\n")
    listed = os.lstat(log)
    sizes: list[int] = []
    opened: list[int] = []
    real_open, real_read = os.open, os.read

    def recording_open(*args: Any, **kwargs: Any) -> int:
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def recording_read(fd: int, n: int) -> bytes:
        # Only the descriptor the read opened, so another thread's read is not counted.
        if fd in opened:
            sizes.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "read", recording_read)
    assert bundle_mod._read_log_file(log, listed) == "last\n"
    assert sizes and all(n <= 33 for n in sizes), sizes


def test_read_log_file_one_byte_over_the_bound_drops_the_cut_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file one byte longer than the bound starts its read at byte 0, and its first line is
    still cut by the bound, so it is still dropped."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 11)
    log = tmp_path / "engine.log"
    log.write_bytes(b"abcdefgh\nxy\n")
    assert bundle_mod._read_log_file(log, os.lstat(log)) == "xy\n"


@pytest.mark.parametrize("body", [b"short\n" + b"z" * 100, b"short\n" + b"z" * 100 + b"\n"])
def test_log_tail_a_last_line_longer_than_the_bound_reports_a_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    """No whole line in the bytes read would leave an empty tail that reads as an empty log, so
    the read reports a code instead."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_bytes(body)
    assert _tail_member(tmp_path, log_dir) == "MF-BUNDLE-LOG-003 _LogLineTooLong"


def test_read_log_file_a_cut_window_of_only_empty_lines_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round 2 kept such a window, but a tail of blank lines renders as an empty member, which
    reads as an empty log; the newest line with content was cut by the bound (BACKLOG #5385)."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log = tmp_path / "engine.log"
    log.write_bytes(b"x" * 40 + b"\n" * 21)
    with pytest.raises(bundle_mod._LogLineTooLong):
        bundle_mod._read_log_file(log, os.lstat(log))


def _shrink_on_lseek(
    monkeypatch: pytest.MonkeyPatch, log: Path, *, times: int, refill: bytes | None = None
) -> list[int]:
    """Truncate ``log`` in place on each of the first ``times`` seeks made on a descriptor
    ``os.open`` returned for ``log``, which falls after the read's fstat and before its read.
    With ``refill``, the file is rewritten with it, in place, before each such open. Another
    descriptor's seek, on this thread or another, runs unchanged. Returns the descriptors
    seen, one entry per seek."""
    real_open, real_lseek = os.open, os.lseek
    opened: list[int] = []
    seeks: list[int] = []

    def recording_open(path: Any, *args: Any, **kwargs: Any) -> int:
        ours = Path(path) == log
        if ours and refill is not None:
            log.write_bytes(refill)
        fd = real_open(path, *args, **kwargs)
        if ours:
            opened.append(fd)
        return fd

    def truncating_lseek(fd: int, pos: int, how: int) -> int:
        if fd in opened:
            seeks.append(fd)
            if len(seeks) <= times:
                log.write_bytes(b"")  # truncated in place after the fstat, before the read
        return real_lseek(fd, pos, how)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "lseek", truncating_lseek)
    return seeks


def test_log_tail_a_file_truncated_while_it_is_read_is_read_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copytruncate rotation between the fstat and the read leaves the read short; the tail is
    listed and read again rather than reported as a long line."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "engine.log"
    log.write_bytes(b"old line\n" * 10)
    seeks = _shrink_on_lseek(monkeypatch, log, times=1)
    assert _tail_member(tmp_path, log_dir) == ""
    assert len(seeks) == 2, seeks


def test_log_tail_a_file_that_shrinks_twice_reports_a_shrink_not_a_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file shorter than its fstat on both reads used to be reported as ``_LogFileRefused``,
    whose diagnostic says the file was replaced. It was truncated in place, so it is reported
    by its own name (BACKLOG #5385)."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "engine.log"
    log.write_bytes(b"old line\n" * 10)
    seeks = _shrink_on_lseek(monkeypatch, log, times=2, refill=b"old line\n" * 10)
    assert _tail_member(tmp_path, log_dir) == "MF-BUNDLE-LOG-002 _LogFileShrank"
    assert len(seeks) == 2, seeks


@pytest.mark.parametrize("ending", [b"\n\n", b"\r\n\r\n", b"\r\r"])
def test_log_tail_a_long_last_line_then_a_blank_line_reports_a_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: bytes
) -> None:
    """A line longer than the bound followed by one blank line used to leave only that blank
    line in the bytes kept: an empty tail with no code, which reads as an empty log (BACKLOG
    #5385)."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_bytes(b"y" * 40 + ending)
    assert _tail_member(tmp_path, log_dir) == "MF-BUNDLE-LOG-003 _LogLineTooLong"


def test_log_tail_a_long_line_then_a_line_with_content_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control for the test above: a blank line followed by a line with content is a
    tail, so it is kept rather than refused."""
    from messagefoundry.support import bundle as bundle_mod

    monkeypatch.setattr(bundle_mod, "_LOG_TAIL_MAX_BYTES", 32)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_bytes(b"y" * 40 + b"\n\nx\n")
    assert _tail_member(tmp_path, log_dir) == "\nx"


def test_a_long_line_has_its_own_code() -> None:
    """``MF-BUNDLE-LOG-002`` says the file could not be read; a long line was read, so it is
    listed under ``MF-BUNDLE-LOG-003`` and not under 002 (BACKLOG #5385)."""
    from messagefoundry.support import bundle as bundle_mod

    doc = " ".join((bundle_mod._diagnostic.__doc__ or "").split())

    def entry(code: str) -> str:
        return doc.split(f"``{code}``", 1)[1].split("* ``", 1)[0]

    assert "_LogLineTooLong" in entry("MF-BUNDLE-LOG-003")
    assert "_LogLineTooLong" not in entry("MF-BUNDLE-LOG-002")
    assert "_LogFileShrank" in entry("MF-BUNDLE-LOG-002")


def test_the_help_and_phi_md_state_the_read_bound(capsys: pytest.CaptureFixture[str]) -> None:
    """The byte bound is restated in the operator help and the PHI record; both follow the
    constant."""
    from messagefoundry.__main__ import _build_parser
    from messagefoundry.support import bundle as bundle_mod

    mib = f"{bundle_mod._LOG_TAIL_MAX_BYTES // (1024 * 1024)} MiB"
    parser, _ = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["support-bundle", "--help"])
    assert mib in " ".join(capsys.readouterr().out.split())
    phi = (Path(__file__).resolve().parents[1] / "docs" / "PHI.md").read_text(encoding="utf-8")
    row = next(line for line in phi.splitlines() if line.startswith("| **14. "))
    assert mib in row
