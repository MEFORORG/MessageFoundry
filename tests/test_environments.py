# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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


def test_resolve_env_settings_reports_missing_and_uncastable_together() -> None:
    settings = {"host": env("a_host"), "port": env("b_port", cast=int)}
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(settings, {"b_port": "notnum"})  # a_host missing + b_port uncastable
    msg = str(ei.value)
    assert "missing: a_host" in msg and "b_port" in msg


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
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="peer_host"):
        runner.build_check(reg)


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
