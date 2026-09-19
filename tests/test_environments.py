# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-environment values (DEV/PROD): ``env()`` references resolve per instance and fail loud if a
referenced value is missing (Part B)."""

from __future__ import annotations

import argparse
import logging
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.environments import (
    load_environment_values,
    resolve_values_base_dir,
)
from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    display_settings,
    env,
    load_config,
    parse_env_setting,
    referenced_env_keys,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _dest_config


def _write(directory: Path, body: str) -> Path:
    (directory / "cfg.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


def test_env_returns_ref() -> None:
    ref = env("epic_host")
    assert isinstance(ref, EnvRef) and ref.key == "epic_host"


def test_resolve_env_settings_resolves_casts_and_defaults() -> None:
    settings = {
        "host": env("epic_host"),
        "port": env("epic_port", cast=int),
        "timeout": env("missing_timeout", default=30.0),  # default used when key absent
        "encoding": "utf-8",  # plain value passes through untouched
    }
    out = resolve_env_settings(settings, {"epic_host": "10.0.0.9", "epic_port": "6661"})
    assert out == {"host": "10.0.0.9", "port": 6661, "timeout": 30.0, "encoding": "utf-8"}


def test_resolve_env_settings_missing_raises_listing_all() -> None:
    settings = {"host": env("a_host"), "port": env("b_port")}
    # All missing keys are reported at once, sorted — fail loud, never a silent blank.
    with pytest.raises(WiringError, match="a_host, b_port"):
        resolve_env_settings(settings, {})


def test_resolve_env_settings_cast_failure_is_wiringerror_not_raw() -> None:
    # A bad value for a cast (a typo'd port) must surface as a WiringError naming the setting/key/
    # value, not a raw ValueError that names nothing (review M-22).
    settings = {"port": env("epic_port", cast=int)}
    with pytest.raises(WiringError, match="epic_port"):
        resolve_env_settings(settings, {"epic_port": "66O1"})  # letter O, not a number


def test_resolve_env_settings_cast_failure_never_echoes_the_value() -> None:
    # The raw value of an env() setting can be a secret -- MEFOR_VALUE_* carries store passwords and
    # connector keys -- and this error string is raised at startup into the operator's log, the support
    # bundle and GET /logs/tail (BACKLOG #1183). It must name the setting and the KEY so the operator
    # can fix it, and never the value. The value used to appear TWICE: once from the f-string and once
    # inside the cast's own ValueError text, so dropping the f-string half alone is not enough.
    secret = "pw-C4st_Val-66"
    settings = {"store_password": env("store_password", cast=int)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"store_password": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the raw env value survived into the error text: {msg!r}"
    # Positive control, and it must assert what THIS change contributes. "store_password" and
    # "uncastable" both survive on the PRE-FIX code -- the name came from the old f-string and
    # "uncastable" from the WiringError wrapper's own header -- so asserting them proves the wrapper
    # works, not that the diagnostic survived the redaction. Measured, not assumed. Pin the two
    # halves the fix actually adds: the expected TYPE, and that withholding is stated rather than
    # silent.
    assert "store_password" in msg
    assert "not a valid int" in msg, (
        f"the expected type is the operator's whole diagnostic: {msg!r}"
    )
    assert "value withheld" in msg, f"a silent redaction reads as a truncated error: {msg!r}"


def test_resolve_env_settings_redacts_a_cast_that_raises_a_non_value_error() -> None:
    # BACKLOG #1656 limb 2, and it is a LEAK, not ergonomics. A cast is an arbitrary callable, so it
    # can raise anything; `except (ValueError, TypeError)` let every other type out of
    # `resolve_env_settings` RAW, and an exception's own text routinely carries the value that
    # provoked it -- a KeyError's text IS the key it was given, which is the measured case below.
    # That re-opened, for every arm but ValueError/TypeError, exactly the leak BACKLOG #1183 closed.
    # `except Exception` puts them all through the one redaction. NEVER BaseException: a
    # KeyboardInterrupt or SystemExit is not a cast failure and must keep propagating.
    secret = "pw-K3yErr_Val-88"

    def _table_cast(raw: object) -> int:
        return {"6661": 6661}[str(raw)]  # a KeyError whose text is the value it was handed

    # Mirrors the production `_cast_bool.__name__ = "bool"` idiom: the diagnostic names the cast the
    # operator wrote, not the helper implementing it.
    _table_cast.__name__ = "int"
    settings = {"store_password": env("store_password", cast=_table_cast)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"store_password": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the raw env value survived into the error text: {msg!r}"
    # Positive controls for what the widened arm contributes: the operator's fix-it (setting, key,
    # expected type) and a STATED redaction, exactly as the ValueError arm above is held.
    assert "store_password" in msg
    assert "not a valid int" in msg, f"the expected type is the whole diagnostic: {msg!r}"
    assert "value withheld" in msg, f"a silent redaction reads as a truncated error: {msg!r}"
    assert "KeyError" in msg, f"the exception TYPE is named; only its text is withheld: {msg!r}"


def test_resolve_env_settings_batches_a_non_value_error_cast_with_other_failures() -> None:
    # The widened arm must also keep the BATCHING promise: an escaping exception aborted on the
    # first bad value and hid every other problem. One report naming all of them is what
    # distinguishes catching from merely not-crashing.
    def _table_cast(raw: object) -> int:
        return {"6661": 6661}[str(raw)]

    _table_cast.__name__ = "int"
    settings = {"host": env("a_host"), "port": env("b_port", cast=_table_cast)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "notaport"})  # a_host missing + b_port KeyError
    msg = str(ei.value)
    # Name the CLAUSE, not just the key. `"b_port" in msg` alone passes if b_port were reported
    # under `missing:` instead -- the two clauses are concatenated into one string, so a bare
    # substring test cannot tell which one carried it, and the whole point here is that the
    # KeyError reached the UNCASTABLE clause rather than ending the pass.
    assert "missing: a_host" in msg
    assert "uncastable: setting 'port' (env 'b_port')" in msg, f"wrong clause: {msg!r}"
    # Redaction must hold in the BATCHED report too, not only in the single-failure one above: a
    # regression that put the raw value back would most plausibly land in exactly this shared line.
    assert "notaport" not in msg, f"the raw env value survived into the batched error: {msg!r}"


def test_resolve_env_settings_redacts_whatever_the_casts_name_turns_out_to_be() -> None:
    # The message interpolates exactly two things the caller controls: `type(exc).__name__` and
    # `want`, the cast's name. `want` is `getattr(cast, "__name__", None) or
    # type(cast).__name__`, and the tests above all override `__name__` to "int" to mirror the
    # production `_cast_bool` idiom -- so neither of its real shapes was ever exercised. Both are
    # pinned here, because a NAME is the only other channel by which the value could reach the
    # operator's error text.
    secret = "pw-K3yErr_Val-88"  # the #1656 needle, reused so no new .gitleaks.toml entry is owed

    def lookup_a_port(raw: object) -> int:  # a code-first cast keeping its own __name__
        return {"6661": 6661}[str(raw)]

    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"port": env("p", cast=lookup_a_port)}, {"p": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the raw env value survived into the error text: {msg!r}"
    # `_NAMED_CASTS` only ever yields int/float/bool/str, none of which raise a non-ValueError, so
    # this wording -- the operator's OWN function name -- is the one a real KeyError case produces.
    assert "not a valid lookup_a_port" in msg, f"the cast's real name is the diagnostic: {msg!r}"

    class TableCast:  # a callable OBJECT: no __name__ at all, so the fallback arm runs
        def __call__(self, raw: object) -> int:
            return {"6661": 6661}[str(raw)]

    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"port": env("p", cast=TableCast())}, {"p": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the fallback arm leaked the value: {msg!r}"
    assert "not a valid TableCast" in msg, f"the fallback names the cast's TYPE: {msg!r}"
    assert "value withheld" in msg and "KeyError" in msg


def test_resolve_env_settings_reports_missing_and_uncastable_together() -> None:
    settings = {"host": env("a_host"), "port": env("b_port", cast=int)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "notnum"})  # a_host missing + b_port uncastable
    msg = str(ei.value)
    assert "missing: a_host" in msg and "b_port" in msg


def _bool_ref(key: str = "flag") -> EnvRef:
    """An env ref carrying the NAMED ``cast = "bool"``, decoded exactly as ``connections.toml`` is.

    Going through :func:`parse_env_setting` rather than ``env(cast=...)`` is the point: the defect
    below lived in the name→callable table, so a test that hands ``resolve_env_settings`` its own
    callable would pass over the broken mapping without touching it."""
    ref = parse_env_setting({"env": key, "cast": "bool"})
    assert isinstance(ref, EnvRef)
    return ref


@pytest.mark.parametrize(
    "spelling", ["true", "True", "TRUE", "1", "yes", "YES", "on", "On", " true "]
)
def test_named_bool_cast_reads_every_true_spelling(spelling: str) -> None:
    out = resolve_env_settings({"flag": _bool_ref()}, {"flag": spelling})
    assert out["flag"] is True  # `is`, not `==`: `1 == True`, so equality would not pin the type


@pytest.mark.parametrize(
    "spelling", ["false", "False", "FALSE", "0", "no", "NO", "off", "Off", " false "]
)
def test_named_bool_cast_reads_every_false_spelling(spelling: str) -> None:
    # The whole defect (BACKLOG #1651). The named cast was the builtin ``bool``, and ``bool(str)`` is
    # True for EVERY non-empty string, so each of these resolved to True -- the inverse of what the
    # operator wrote, with only an unset/empty value ever reading False. These assertions fail on the
    # pre-fix code and the True ones above pass on it, so this half is the one carrying the guard.
    out = resolve_env_settings({"flag": _bool_ref()}, {"flag": spelling})
    assert out["flag"] is False


@pytest.mark.parametrize(("raw", "want"), [(True, True), (False, False), (1, True), (0, False)])
def test_named_bool_cast_passes_typed_toml_values_through(raw: object, want: bool) -> None:
    # environments/<env>.toml is TOML, so a native ``flag = true`` (or ``flag = 1``) reaches the cast
    # already typed rather than as text. Re-parsing a real bool would be this same defect in reverse.
    assert resolve_env_settings({"flag": _bool_ref()}, {"flag": raw})["flag"] is want


@pytest.mark.parametrize("raw", ["maybe", "", "   ", "2", "truthy", "y", 2, -1, None, 1.5])
def test_named_bool_cast_refuses_an_unreadable_value(raw: object) -> None:
    # An unrecognized spelling has no honest reading, so it fails loud the way a bad ``int`` does
    # rather than guessing a side. The empty string is deliberately in here: pre-fix it was the ONLY
    # value that read False, and "the operator left it unset" is not evidence they meant False.
    with pytest.raises(WiringError, match="not a valid bool"):
        resolve_env_settings({"debug": _bool_ref("debug_flag")}, {"debug_flag": raw})


def test_named_bool_cast_failure_renders_the_operator_diagnostic() -> None:
    # Pins the rendered sentence, because two separate things feed it and neither is obvious at the
    # cast. ``resolve_env_settings`` names the expected TYPE from the cast callable's ``__name__``, so
    # a helper named ``_parse_bool`` (or a lambda) would render "not a valid _parse_bool" / "not a
    # valid <lambda>" -- a silent regression in operator-facing text that no other assertion catches.
    # And the value must never appear: a MEFOR_VALUE_* setting carries store passwords and connector
    # keys, and this string reaches the operator log, the support bundle and GET /logs/tail
    # (BACKLOG #1183, the same rule the int cast above is held to).
    secret = "pw-B00l_Val-77"
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"debug": _bool_ref("debug_flag")}, {"debug_flag": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the raw env value survived into the error text: {msg!r}"
    assert "debug" in msg and "debug_flag" in msg, f"the setting and key are the fix-it: {msg!r}"
    assert "not a valid bool" in msg, f"the expected type is the operator's diagnostic: {msg!r}"
    assert "value withheld" in msg, f"a silent redaction reads as a truncated error: {msg!r}"


def test_named_bool_cast_batches_with_other_failures() -> None:
    # The bool parser's failure must be BATCHED with the others rather than ending the pass.
    #
    # THIS COMMENT USED TO SAY a WiringError raised from inside the cast "would propagate past that
    # handler, skipping BOTH the batching and the redaction". That was true of `except (ValueError,
    # TypeError)` and is FALSE now: BACKLOG #1656 limb 2 widened the handler to `except Exception`,
    # which catches a cast's own WiringError too and redacts it like any other. So the reason the
    # bool parser raises ValueError is no longer escape -- it is that a cast should fail the way
    # every other cast fails, and not lean on the catch-all to tidy up after it.
    #
    # A WiringError arrives here either way, so only a report naming every problem at once
    # distinguishes batching from merely not-crashing.
    settings = {"host": env("a_host"), "port": env("b_port", cast=int), "debug": _bool_ref()}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "notnum", "flag": "perhaps"})
    msg = str(ei.value)
    assert "missing: a_host" in msg and "b_port" in msg and "debug" in msg


def test_referenced_env_keys_and_display() -> None:
    settings = {"host": env("h"), "port": env("p", default=1), "x": "lit"}
    assert referenced_env_keys(settings) == ["h", "p"]
    assert display_settings(settings) == {
        "host": {"env": "h"},
        "port": {"env": "p", "default": 1},
        "x": "lit",
    }


def test_load_environment_values_file_and_env_overlay(tmp_path: Path) -> None:
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "dev.toml").write_text('a_host = "127.0.0.1"\na_port = 2601\n', encoding="utf-8")
    values = load_environment_values(
        base_dir=tmp_path,
        dir_name="environments",
        environment="dev",
        environ={"MEFOR_VALUE_A_HOST": "10.0.0.1", "MEFOR_VALUE_SECRET": "s3cret"},
    )
    assert values["a_host"] == "10.0.0.1"  # env overrides the file
    assert values["a_port"] == 2601  # file value (TOML int preserved)
    assert values["secret"] == "s3cret"  # env-only value (e.g. a secret)


def test_load_environment_values_lowercases_file_keys(tmp_path: Path) -> None:
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "prod.toml").write_text('EPIC_HOST = "10.0.0.9"\n', encoding="utf-8")
    # The file key folds to lower-case, so a MEFOR_VALUE_* override (also lower-cased) wins over it
    # rather than forking into two separate entries.
    values = load_environment_values(
        base_dir=tmp_path,
        dir_name="environments",
        environment="prod",
        environ={"MEFOR_VALUE_EPIC_HOST": "10.9.9.9"},
    )
    assert values == {"epic_host": "10.9.9.9"}


def test_env_ref_key_is_lowercased() -> None:
    assert env("EPIC_HOST").key == "epic_host"
    # a mixed-case reference resolves against the lower-cased values
    out = resolve_env_settings({"host": env("Epic_Host")}, {"epic_host": "10.0.0.1"})
    assert out["host"] == "10.0.0.1"


def test_load_environment_values_missing_file_is_empty(tmp_path: Path) -> None:
    assert (
        load_environment_values(
            base_dir=tmp_path, dir_name="environments", environment="prod", environ={}
        )
        == {}
    )


def test_build_resolves_env_outbound(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP, env
        outbound("OB", MLLP(host=env("peer_host"), port=env("peer_port", cast=int)))
        """,
    )
    reg = load_config(d)
    dest = _dest_config(reg.outbound["OB"], {"peer_host": "10.0.0.2", "peer_port": "6000"})
    assert dest.settings["host"] == "10.0.0.2"
    assert dest.settings["port"] == 6000


def test_build_check_fails_loud_on_missing_env_value(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP, env
        outbound("OB", MLLP(host=env("peer_host"), port=2601))
        """,
    )
    reg = load_config(d)
    # A missing value is refused when the connector is built (here, on this instance) — exactly the
    # promote-time guarantee: a graph whose env keys aren't defined for the target never goes live.
    # This guarantee is UNCHANGED by the #233 not-deployed carve-out below: it is scoped to the flag,
    # not a general softening — a DEPLOYED connection (the default, so: every existing one) still
    # fails loud on an env key the target environment does not define.
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="peer_host"):
        runner.build_check(reg)


def test_build_check_does_not_resolve_env_for_a_not_deployed_connection(tmp_path: Path) -> None:
    """The sibling carve-out (#233, ADR 0111): a connection declared ``deployed=false`` is skipped by
    the build check, so its ``env()`` refs are never resolved and its absent values never raise.

    That is what makes the state usable at all — ``build_check`` is what ``messagefoundry check`` (the
    required commit gate), every reload/promote and every ``connection upsert`` run, so a partner whose
    credentials are not provisioned yet would otherwise block all of them (and, today, block edits to
    every OTHER connection too). The connection stays in the graph; only its BUILD is skipped."""
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP, env
        outbound("OB", MLLP(host=env("peer_host"), port=2601), deployed=False)
        """,
    )
    reg = load_config(d)
    assert "OB" in reg.outbound and reg.outbound["OB"].deployed is False  # still IN the graph
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    runner.build_check(reg)  # must not raise — 'peer_host' is never looked up


def test_committed_environment_files_define_the_same_keys() -> None:
    """The shipped message graph (samples/config) is identical across environments, so every env()
    value a feed needs must be present in EVERY environments/<env>.toml — only the values differ
    (secrets come from MEFOR_VALUE_*). prod.toml's own header promises "same keys as dev.toml".

    A key in one file but missing from another means a `serve`/promote in the lean environment fails
    loud at graph start. The prod service-smoke caught exactly this once (a SOAP/RTE feed's keys were
    added to dev.toml but not prod.toml, so the engine refused to start in prod); guard it here so the
    drift is caught on every PR, not only on push-to-main.
    """
    import tomllib

    env_dir = Path(__file__).resolve().parents[1] / "environments"
    files = sorted(env_dir.glob("*.toml"))
    assert files, f"no environment value files found under {env_dir}"
    keysets: dict[str, set[str]] = {}
    for f in files:
        with f.open("rb") as fh:
            keysets[f.name] = {k.lower() for k in tomllib.load(fh)}
    union = set().union(*keysets.values())
    missing = {name: sorted(union - ks) for name, ks in keysets.items() if union - ks}
    assert not missing, (
        f"environment value files disagree on keys (each must define all of {sorted(union)}): {missing}"
    )


# --- WS-1: anchoring environments/<env>.toml to a project root (ADR 0017) --------------------------


def test_resolve_values_base_dir_empty_is_cwd(tmp_path: Path) -> None:
    # Empty base_dir = the original behavior: resolve against the process working dir (here, cwd arg).
    assert resolve_values_base_dir("", cwd=tmp_path) == tmp_path


def test_resolve_values_base_dir_relative_anchors_to_cwd(tmp_path: Path) -> None:
    # A relative anchor is taken against cwd (so `--project-root sub` is cwd/sub, predictable).
    assert resolve_values_base_dir("repo", cwd=tmp_path) == tmp_path / "repo"


def test_resolve_values_base_dir_absolute_wins(tmp_path: Path) -> None:
    # An absolute anchor (the NSSM case: pin the repo root) is used as-is, ignoring cwd.
    other = tmp_path / "elsewhere"
    abs_root = (tmp_path / "abs_repo").resolve()
    assert resolve_values_base_dir(str(abs_root), cwd=other) == abs_root


def test_resolve_values_base_dir_warns_on_rooted_but_not_absolute_anchor(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A backslash-rooted anchor is drive-relative (not truly absolute) on BOTH Windows and POSIX, so it
    # still resolves against cwd — the exact launch-dependence the anchor exists to remove. It must warn
    # loud (so the silent-wrong-drive footgun surfaces) while still returning the cwd-joined path.
    rooted = "\\rooted\\not\\absolute"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.environments"):
        result = resolve_values_base_dir(rooted, cwd=tmp_path)
    assert "not fully absolute" in caplog.text
    assert result == tmp_path / rooted  # behavior unchanged — the warning doesn't alter resolution


def test_resolve_values_base_dir_no_warning_for_relative_or_drive_qualified(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A plain relative anchor (intended) and a drive-qualified absolute one must NOT warn.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.environments"):
        resolve_values_base_dir(
            "sub/anchor", cwd=tmp_path
        )  # relative — the documented relative case
        resolve_values_base_dir(
            "C:/repo", cwd=tmp_path
        )  # drive-qualified (Win) / plain name (POSIX)
    assert "not fully absolute" not in caplog.text


def test_anchor_finds_value_file_when_cwd_is_elsewhere(tmp_path: Path) -> None:
    """The fix: with an explicit anchor, env values resolve no matter where serve was launched."""
    repo = tmp_path / "config-repo"
    (repo / "environments").mkdir(parents=True)
    (repo / "environments" / "dev.toml").write_text('acme_host = "10.0.0.7"\n', encoding="utf-8")
    launched_from = tmp_path / "some-service-workdir"  # NOT the repo (e.g. NSSM's AppDirectory)
    launched_from.mkdir()

    # Anchored at the repo root -> the file is found even though cwd is the unrelated work dir.
    base = resolve_values_base_dir(str(repo), cwd=launched_from)
    anchored = load_environment_values(
        base_dir=base, dir_name="environments", environment="dev", environ={}
    )
    assert anchored == {"acme_host": "10.0.0.7"}


def test_unanchored_default_is_unchanged_and_reproduces_the_footgun(tmp_path: Path) -> None:
    """Back-compat guard: empty base_dir keeps cwd-relative resolution exactly as before — which is
    precisely why a serve launched outside the repo silently reads no values (the footgun this anchor
    fixes). Locks the default in so the opt-in can't accidentally change it."""
    repo = tmp_path / "config-repo"
    (repo / "environments").mkdir(parents=True)
    (repo / "environments" / "dev.toml").write_text('acme_host = "10.0.0.7"\n', encoding="utf-8")
    launched_from = tmp_path / "some-service-workdir"
    launched_from.mkdir()

    # Empty anchor -> resolves against the (wrong) cwd, which has no environments/ -> empty, not error.
    base = resolve_values_base_dir("", cwd=launched_from)
    assert base == launched_from
    unanchored = load_environment_values(
        base_dir=base, dir_name="environments", environment="dev", environ={}
    )
    assert unanchored == {}


def test_environments_settings_base_dir_default_and_overrides(tmp_path: Path) -> None:
    from messagefoundry.config.settings import EnvironmentsSettings, load_settings

    # Default is empty (cwd behavior preserved).
    assert EnvironmentsSettings().base_dir == ""

    # From the config file...
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[environments]\nbase_dir = "C:/repo"\n', encoding="utf-8")
    from_file = load_settings(config_path=cfg, environ={})
    assert from_file.environments.base_dir == "C:/repo"

    # ...and env overrides the file (MEFOR_<SECTION>_<KEY>), like every other service setting.
    from_env = load_settings(config_path=cfg, environ={"MEFOR_ENVIRONMENTS_BASE_DIR": "D:/other"})
    assert from_env.environments.base_dir == "D:/other"


def test_base_dir_setting_flows_through_to_resolution(tmp_path: Path) -> None:
    """End-to-end of the serve wiring (sans server): a [environments].base_dir in the instance config
    is what env-value resolution anchors on, independent of cwd."""
    from messagefoundry.config.settings import load_settings

    repo = tmp_path / "repo"
    (repo / "environments").mkdir(parents=True)
    (repo / "environments" / "prod.toml").write_text('db_host = "db.internal"\n', encoding="utf-8")

    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(f"[environments]\nbase_dir = {str(repo)!r}\n", encoding="utf-8")
    settings = load_settings(config_path=cfg, environ={})

    base = resolve_values_base_dir(settings.environments.base_dir, cwd=tmp_path / "anywhere")
    values = load_environment_values(
        base_dir=base, dir_name=settings.environments.dir, environment="prod", environ={}
    )
    assert values == {"db_host": "db.internal"}


def test_serve_project_root_flag_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """`serve --project-root` reaches args through the real CLI parser (defaulting to None when
    omitted). Patches the dispatch entry so no server starts."""
    from messagefoundry import __main__ as cli

    captured: dict[str, argparse.Namespace] = {}

    def _capture(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setitem(cli._DISPATCH, "serve", _capture)

    assert (
        cli.main(["serve", "--config", "c", "--env", "dev", "--project-root", "C:/srv/repo"]) == 0
    )
    assert captured["args"].project_root == "C:/srv/repo"

    captured.clear()
    assert cli.main(["serve", "--config", "c", "--env", "dev"]) == 0
    assert captured["args"].project_root is None  # default: unchanged cwd behavior
