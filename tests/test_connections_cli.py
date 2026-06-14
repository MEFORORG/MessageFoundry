"""`messagefoundry connection list|upsert|remove` — the comment-preserving connections.toml editor
the VS Code GUI shells (ADR 0007). Validates-before-persist and rolls back on failure."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.wiring import load_config

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


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    (tmp_path / "logic.py").write_text(LOGIC, encoding="utf-8")
    return tmp_path


def _svc(cfg: Path, body: str = "") -> Path:
    path = cfg / "svc.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _upsert(cfg: Path, obj: dict, capsys, *, svc: Path | None = None) -> tuple[int, str]:
    args = ["connection", "upsert", "--config", str(cfg), "--data", json.dumps(obj), "--json"]
    if svc is not None:
        args += ["--service-config", str(svc)]
    rc = main(args)
    return rc, capsys.readouterr().out


def test_upsert_creates_and_reloads(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    rc, _ = _upsert(cfg, obj, capsys, svc=_svc(cfg))
    assert rc == 0
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert 'name = "IB"' in text and "port = 2600" in text
    reg = load_config(cfg)
    assert reg.inbound["IB"].router == "r" and reg.inbound["IB"].spec.settings["port"] == 2600


def test_upsert_replaces_in_place(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(cfg)
    base = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    assert _upsert(cfg, base, capsys, svc=svc)[0] == 0
    assert _upsert(cfg, {**base, "settings": {"port": 2601}}, capsys, svc=svc)[0] == 0
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert text.count('name = "IB"') == 1  # replaced, not duplicated
    assert load_config(cfg).inbound["IB"].spec.settings["port"] == 2601


def test_invalid_upsert_is_not_persisted(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "nope",  # no such router
        "settings": {"port": 2600},
    }
    rc, out = _upsert(cfg, obj, capsys, svc=_svc(cfg))
    assert rc == 1
    assert "unknown router" in out
    assert not (cfg / "connections.toml").exists()  # nothing written


def test_failed_edit_rolls_back(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(cfg)
    good = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    assert _upsert(cfg, good, capsys, svc=svc)[0] == 0
    original = (cfg / "connections.toml").read_text(encoding="utf-8")
    bad = {
        "direction": "inbound",
        "name": "IB2",
        "transport": "mllp",
        "router": "nope",
        "settings": {"port": 2602},
    }
    assert _upsert(cfg, bad, capsys, svc=svc)[0] == 1
    assert (cfg / "connections.toml").read_text(
        encoding="utf-8"
    ) == original  # rolled back byte-stable


def test_remove(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(cfg)
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    assert _upsert(cfg, obj, capsys, svc=svc)[0] == 0
    rc = main(
        ["connection", "remove", "--config", str(cfg), "--service-config", str(svc), "--name", "IB"]
    )
    capsys.readouterr()
    assert rc == 0
    assert "IB" not in load_config(cfg).inbound


def test_remove_missing_fails(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # no connections.toml at all
    rc = main(["connection", "remove", "--config", str(cfg), "--name", "NOPE", "--json"])
    assert rc == 1 and "no connections.toml" in capsys.readouterr().out
    # file exists but the name isn't in it (and can't remove a code-authored connection here)
    svc = _svc(cfg)
    _upsert(
        cfg,
        {
            "direction": "inbound",
            "name": "IB",
            "transport": "mllp",
            "router": "r",
            "settings": {"port": 2600},
        },
        capsys,
        svc=svc,
    )
    rc = main(["connection", "remove", "--config", str(cfg), "--name", "NOPE", "--json"])
    assert rc == 1 and "is not in connections.toml" in capsys.readouterr().out


def test_egress_deny_blocks_upsert(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(cfg, '[egress]\nallowed_mllp = ["10.0.0.1:6000"]\n')
    obj = {
        "direction": "outbound",
        "name": "OB",
        "transport": "mllp",
        "settings": {"host": "evil.example", "port": 6000},
    }
    rc, out = _upsert(cfg, obj, capsys, svc=svc)
    assert rc == 1
    assert "allowed_mllp" in out
    assert not (cfg / "connections.toml").exists()  # egress-denied edit never lands


def test_hand_comment_survives_gui_upsert(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A developer hand-writes a commented connection...
    (cfg / "connections.toml").write_text(
        textwrap.dedent(
            """
            # hand-written — keep this header comment
            [[inbound]]
            name = "HAND"  # important inline note
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2599
            """
        ),
        encoding="utf-8",
    )
    # ...then the GUI upserts a DIFFERENT connection via the CLI.
    obj = {
        "direction": "outbound",
        "name": "OB",
        "transport": "mllp",
        "settings": {"host": "epic.example", "port": 2700},
    }
    assert _upsert(cfg, obj, capsys, svc=_svc(cfg))[0] == 0
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert "# hand-written — keep this header comment" in text  # untouched table's comments survive
    assert "# important inline note" in text
    assert 'name = "OB"' in text  # the new one was added
    reg = load_config(cfg)
    assert "HAND" in reg.inbound and "OB" in reg.outbound


def test_list_returns_entries(cfg: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(cfg)
    assert (
        _upsert(
            cfg,
            {
                "direction": "inbound",
                "name": "IB",
                "transport": "mllp",
                "router": "r",
                "settings": {"port": 2600},
            },
            capsys,
            svc=svc,
        )[0]
        == 0
    )
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    entries = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert any(e["name"] == "IB" and e["direction"] == "inbound" for e in entries)
