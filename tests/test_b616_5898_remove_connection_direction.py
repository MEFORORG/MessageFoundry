# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`connection remove` names the direction when an inbound and an outbound share a name (BACKLOG
#5898). The loader keeps the two tables apart, so ``X`` may be both. Removal used to take the
first match in inbound-then-outbound order, so removing the outbound ``X`` removed the inbound."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config import connections_edit
from messagefoundry.config.wiring import WiringError, load_config

LOGIC = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB", msg)
    """
)


def _noop(_path: Path) -> None:
    return None


@pytest.fixture
def cfg(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[Path, Path]:
    """A config dir whose connections.toml holds inbound X, outbound X and outbound OB."""
    (tmp_path / "logic.py").write_text(LOGIC, encoding="utf-8")
    svc = tmp_path / "svc.toml"
    # The edit's build check runs under the egress deny default (vault BACKLOG #2605).
    svc.write_text(f"[egress]\nallowed_file_dirs = ['{tmp_path}']\n", encoding="utf-8")
    conns = [
        {
            "direction": "inbound",
            "name": "X",
            "transport": "mllp",
            "router": "r",
            "settings": {"port": 2600},
        },
        {
            "direction": "outbound",
            "name": "X",
            "transport": "file",
            "settings": {"directory": str(tmp_path / "out_x")},
        },
        {
            "direction": "outbound",
            "name": "OB",
            "transport": "file",
            "settings": {"directory": str(tmp_path / "out_ob")},
        },
    ]
    for obj in conns:
        rc = main(
            ["connection", "upsert", "--config", str(tmp_path), "--service-config", str(svc)]
            + ["--data", json.dumps(obj), "--json"]
        )
        assert rc == 0, capsys.readouterr().out
    capsys.readouterr()
    reg = load_config(tmp_path)
    assert "X" in reg.inbound and "X" in reg.outbound  # the loader accepts the shared name
    return tmp_path, svc


def _remove(cfg: Path, svc: Path, *extra: str) -> int:
    return main(
        ["connection", "remove", "--config", str(cfg), "--service-config", str(svc)]
        + ["--name", "X", "--json", *extra]
    )


def test_remove_outbound_keeps_the_same_named_inbound(
    cfg: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir, svc = cfg
    assert _remove(config_dir, svc, "--direction", "outbound") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["direction"] == "outbound"
    reg = load_config(config_dir)
    assert "X" in reg.inbound
    assert "X" not in reg.outbound


def test_remove_inbound_keeps_the_same_named_outbound(
    cfg: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir, svc = cfg
    assert _remove(config_dir, svc, "--direction", "inbound") == 0
    capsys.readouterr()
    reg = load_config(config_dir)
    assert "X" not in reg.inbound
    assert "X" in reg.outbound


def test_ambiguous_name_without_direction_is_refused_and_nothing_removed(
    cfg: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir, svc = cfg
    before = (config_dir / "connections.toml").read_bytes()
    assert _remove(config_dir, svc) == 1
    out = capsys.readouterr().out
    assert "both an inbound and an outbound" in out
    assert "pass --direction inbound or --direction outbound" in out
    assert (config_dir / "connections.toml").read_bytes() == before


def test_unique_name_still_removes_without_direction(cfg: tuple[Path, Path]) -> None:
    config_dir, _svc = cfg
    result = connections_edit.remove_connection(config_dir, "OB", validate=_noop)
    assert result == {"op": "remove", "direction": "outbound", "name": "OB"}


def test_direction_that_does_not_hold_the_name_is_refused(cfg: tuple[Path, Path]) -> None:
    config_dir, _svc = cfg
    before = (config_dir / "connections.toml").read_bytes()
    with pytest.raises(WiringError, match="it holds 'OB' only as an outbound"):
        connections_edit.remove_connection(config_dir, "OB", validate=_noop, direction="inbound")
    assert (config_dir / "connections.toml").read_bytes() == before


def test_direction_is_refused_outside_remove(
    cfg: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir, _svc = cfg
    rc = main(
        ["connection", "list", "--config", str(config_dir), "--direction", "inbound", "--json"]
    )
    assert rc == 1
    assert "--direction applies only to `connection remove`" in capsys.readouterr().out


def test_a_name_repeated_in_one_direction_still_removes_its_first_match(tmp_path: Path) -> None:
    # A hand-written duplicate the loader refuses; `remove` stays the repair for it, and the
    # shared-name refusal is only for a name held in BOTH directions.
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            """
            [[inbound]]
            name = "X"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2600
            [[inbound]]
            name = "X"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2601
            """
        ),
        encoding="utf-8",
    )
    result = connections_edit.remove_connection(tmp_path, "X", validate=_noop)
    assert result["direction"] == "inbound"
    text = (tmp_path / "connections.toml").read_text(encoding="utf-8")
    assert text.count('name = "X"') == 1 and "port = 2601" in text


def test_a_bad_direction_is_refused_as_the_argument(cfg: tuple[Path, Path]) -> None:
    config_dir, _svc = cfg
    with pytest.raises(WiringError, match="direction must be 'inbound' or 'outbound'"):
        connections_edit.remove_connection(
            config_dir,
            "X",
            validate=_noop,
            direction="Inbound",  # type: ignore[arg-type]
        )
