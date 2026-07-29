# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
        # ADR 0153: `connection upsert` validates the edit through the posture-stamped build_check, and
        # a plaintext MLLP hop to an off-box host now REFUSES with no data-label carve-out. Declaring
        # the acceptance is what makes the edit load-legal — and proves the new keys survive the
        # comment-preserving writer, which is the property this test is really about.
        "cleartext_accepted": True,
        "cleartext_reason": "legacy partner has no MLLP-over-TLS listener",
    }
    assert _upsert(cfg, obj, capsys, svc=_svc(cfg))[0] == 0
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert "# hand-written — keep this header comment" in text  # untouched table's comments survive
    assert "# important inline note" in text
    assert 'name = "OB"' in text  # the new one was added
    reg = load_config(cfg)
    assert "HAND" in reg.inbound and "OB" in reg.outbound


# --- #234 Phase 2: list canonicalization, byte-idempotence, CLI end-to-end ----

# A schedule with TOML-NATIVE times (07:00:00 unquoted — tomlkit unwraps them to datetime.time).
# Hand-authoring this shape is legal on the read path, so `connection list` must survive it.
_NATIVE_SCHEDULE_TOML = """
[[inbound]]
name = "IB_SCHED"
transport = "mllp"
router = "r"
  [inbound.settings]
  port = 2600
  [inbound.schedule]
  invert = false
  windows = [ { days = [0, 1, 2, 3, 4], start = 07:00:00, end = 17:00:00 } ]

[[inbound]]
name = "IB_PLAIN"
transport = "mllp"
router = "r"
  [inbound.settings]
  port = 2601
"""


def test_list_canonicalizes_toml_native_schedule_times(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#234 Phase 2 regression (red-first): `connection list` on a config whose schedule used
    TOML-native times crashed with an uncaught TypeError (json.dumps met datetime.time inside
    _print_json) — killing the listing for the WHOLE file, not just the scheduled connection. Fixed by
    canonicalizing at the LIST BOUNDARY (connections_edit.list_connections) — deliberately NOT via a
    ``default=`` hook on _print_json, so the CLI, the IDE's runJson, and direct Python callers all see
    one canonical form; ``messagefoundry/__main__.py`` is deliberately UNCHANGED."""
    (cfg / "connections.toml").write_text(textwrap.dedent(_NATIVE_SCHEDULE_TOML), encoding="utf-8")
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    entries = json.loads(capsys.readouterr().out)
    assert rc == 0
    sched = next(e for e in entries if e["name"] == "IB_SCHED")
    assert sched["schedule"]["windows"][0]["start"] == "07:00:00"
    assert sched["schedule"]["windows"][0]["end"] == "17:00:00"
    # The whole file lists — the unscheduled sibling was a casualty of the crash too.
    assert any(e["name"] == "IB_PLAIN" for e in entries)


def test_second_identical_upsert_is_byte_idempotent(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#234 Phase 2 (NEW guarantee): a second identical upsert — and the GUI's no-op re-save
    (list → upsert of the listed entry) — leaves the file byte-identical, so a save that changes
    nothing produces a clean config-repo diff."""
    svc = _svc(cfg)
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
        "source_ip_allowlist": ["10.0.0.8", "10.0.1.0/24"],
        "metadata": {"site": "main-campus"},
        "schedule": {
            "windows": [{"days": [0, 1, 2, 3, 4], "start": "07:00:00", "end": "17:00:00"}],
            "invert": False,
        },
    }
    assert _upsert(cfg, obj, capsys, svc=svc)[0] == 0
    first = (cfg / "connections.toml").read_text(encoding="utf-8")
    # (a) the same --data posted again
    assert _upsert(cfg, obj, capsys, svc=svc)[0] == 0
    assert (cfg / "connections.toml").read_text(encoding="utf-8") == first
    # (b) the GUI's no-op re-save: list → upsert the listed entry verbatim
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    assert rc == 0
    [entry] = json.loads(capsys.readouterr().out)
    assert _upsert(cfg, entry, capsys, svc=svc)[0] == 0
    assert (cfg / "connections.toml").read_text(encoding="utf-8") == first


def test_cli_end_to_end_maximal_with_commented_sibling(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#234 Phase 2 end-to-end through main(): a hand-commented sibling table + rich both-direction
    tables (TOML-native schedule times) → `list --json` → `upsert --data` each listed entry → reload
    equality; the untouched sibling's comments survive (honestly: COMMENT-SUBSTRING survival — the
    touched tables' own style is legitimately rewritten by full-replace)."""
    (cfg / "connections.toml").write_text(
        textwrap.dedent(
            """
            # estate config — keep this header comment
            [[inbound]]
            name = "HAND"  # hand-tuned, do not touch
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2599

            [[inbound]]
            name = "IB_RICH"
            transport = "mllp"
            router = "r"
            source_ip_allowlist = ["10.0.0.8"]
            shard = "site-a"
              [inbound.settings]
              port = 2600
              [inbound.schedule]
              invert = false
              windows = [ { days = [0, 1, 2, 3, 4], start = 07:00:00, end = 17:00:00 } ]

            [[outbound]]
            name = "OB_RICH"
            transport = "mllp"
            ordering = "fifo"
            dead_letter_days = 7
            cleartext_accepted = true
            cleartext_reason = "legacy partner has no MLLP-over-TLS listener"
              [outbound.settings]
              host = "epic.example"
              port = 2700
              [outbound.stall]
              max_oldest_seconds = 600.0
              [outbound.metadata]
              owner = "integration-team"
            """
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg)
    before_reg = load_config(cfg)
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    entries = json.loads(capsys.readouterr().out)
    assert rc == 0
    # The GUI re-saves the two rich tables it edited (a no-op edit) — the HAND table is untouched.
    for name in ("IB_RICH", "OB_RICH"):
        [entry] = [e for e in entries if e["name"] == name]
        assert _upsert(cfg, entry, capsys, svc=svc)[0] == 0
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert "# estate config — keep this header comment" in text
    assert "# hand-tuned, do not touch" in text
    after_reg = load_config(cfg)
    ib_before, ib_after = before_reg.inbound["IB_RICH"], after_reg.inbound["IB_RICH"]
    assert ib_after.schedule == ib_before.schedule  # times re-parsed from the ISO-string form
    assert ib_after.source_ip_allowlist == ib_before.source_ip_allowlist
    assert ib_after.shard == ib_before.shard
    ob_before, ob_after = before_reg.outbound["OB_RICH"], after_reg.outbound["OB_RICH"]
    assert ob_after.stall == ob_before.stall
    assert ob_after.metadata == ob_before.metadata
    assert ob_after.dead_letter_days == ob_before.dead_letter_days
    assert "HAND" in after_reg.inbound


def test_upsert_rejects_unknown_key_and_writes_nothing(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#234: the CLI surfaces the writer's fail-loud unknown-key rejection (exit 1, key named) and
    the file is never created — the old writer silently DROPPED unrecognized keys instead."""
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
        "retry": {"max_attempts": 3},  # an OUTBOUND key — unknown for this direction
    }
    rc, out = _upsert(cfg, obj, capsys, svc=_svc(cfg))
    assert rc == 1
    assert "unknown key" in out and "retry" in out
    assert not (cfg / "connections.toml").exists()


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
