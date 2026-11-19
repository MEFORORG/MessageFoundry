# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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


#: The edit's build check runs under the settings model's deny default (vault BACKLOG #2605), so
#: a test whose outbound dials the partner host lists it.
_EPIC_EGRESS = '[egress]\nallowed_mllp = ["epic.example"]\n'


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
    # allow_empty: removing the only connection leaves an empty graph, which load_config refuses by
    # default (BACKLOG #1648). Emptiness is what this test just asserted happened.
    assert "IB" not in load_config(cfg, allow_empty=True).inbound


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
    assert _upsert(cfg, obj, capsys, svc=_svc(cfg, _EPIC_EGRESS))[0] == 0
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
    svc = _svc(cfg, _EPIC_EGRESS)
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


def _strict_json(text: str) -> object:
    def _refuse(token: str) -> object:
        raise ValueError(f"non-standard JSON token {token}")

    return json.loads(text, parse_constant=_refuse)


def test_list_emits_standard_json_for_an_infinite_alert_age(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5778: `inf` is the TOML spelling of an off alert age. `connection list` used to print
    it as a bare Infinity token the IDE's JSON.parse refuses; it now passes a strict parse, loads as
    off, and stays off through the GUI's list -> upsert re-save."""
    (cfg / "connections.toml").write_text(
        textwrap.dedent(
            """\
            [[outbound]]
            name = "OB"
            transport = "mllp"
            cleartext_accepted = true
            cleartext_reason = "legacy partner has no MLLP-over-TLS listener"
              [outbound.settings]
              host = "epic.example"
              port = 2700
              [outbound.buildup]
              max_oldest_seconds = inf
              [outbound.stall]
              max_oldest_seconds = inf
            """
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, _EPIC_EGRESS)
    assert load_config(cfg).outbound["OB"].buildup.max_oldest_seconds is None  # type: ignore[union-attr]
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    entries = _strict_json(out)
    assert isinstance(entries, list)
    [entry] = [e for e in entries if e["name"] == "OB"]
    assert _upsert(cfg, entry, capsys, svc=svc)[0] == 0
    after = load_config(cfg).outbound["OB"]
    assert after.buildup is not None and after.buildup.max_oldest_seconds is None
    assert after.stall is not None and after.stall.max_oldest_seconds is None


_INF_ROUND_TRIP_FILE = """\
[[inbound]]
name = "IB"
transport = "mllp"
router = "r"
{inbound_extra}  [inbound.settings]
  port = 2600

[[outbound]]
name = "OB"
transport = "mllp"
cleartext_accepted = true
cleartext_reason = "legacy partner has no MLLP-over-TLS listener"
{outbound_extra}  [outbound.settings]
  host = "epic.example"
  port = 2700
{outbound_tables}"""

#: Each case sets one field to TOML `inf`, with a trailing comment a rewrite would lose.
_INF_CASES = {
    "strict_timeout_s": {"inbound_extra": "strict_timeout_s = inf  # backstop off\n"},
    "waiting_display_delay": {"outbound_extra": "waiting_display_delay = inf  # never show\n"},
    "buildup.max_oldest_seconds": {
        "outbound_tables": "  [outbound.buildup]\n  max_oldest_seconds = inf  # age off\n"
    },
    "stall.max_oldest_seconds": {
        "outbound_tables": "  [outbound.stall]\n  max_oldest_seconds = inf  # age off\n"
    },
}


def _inf_file(cfg: Path, case: str) -> bytes:
    parts = {"inbound_extra": "", "outbound_extra": "", "outbound_tables": ""} | _INF_CASES[case]
    data = _INF_ROUND_TRIP_FILE.format(**parts).encode("utf-8")
    (cfg / "connections.toml").write_bytes(data)
    return data


def _listed(cfg: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, dict]:
    rc = main(["connection", "list", "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    entries = _strict_json(out)
    assert isinstance(entries, list)
    return {entry["name"]: entry for entry in entries}


@pytest.mark.parametrize("case", sorted(_INF_CASES))
def test_infinite_value_list_upsert_round_trip_is_byte_identical(
    case: str, cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5778: `connection list` prints a non-finite float as the string "inf". Sending the
    listed entry straight back through `connection upsert` (the GUI's no-op save) must leave the
    file byte-identical, keeping the float -- not rewrite it as the string "inf", which the read
    schema refuses for strict_timeout_s and waiting_display_delay."""
    before = _inf_file(cfg, case)
    svc = _svc(cfg, _EPIC_EGRESS)
    for entry in _listed(cfg, capsys).values():
        rc, out = _upsert(cfg, entry, capsys, svc=svc)
        assert rc == 0, out
    assert (cfg / "connections.toml").read_bytes() == before
    load_config(cfg)  # still loads


@pytest.mark.parametrize("case", sorted(_INF_CASES))
def test_infinite_value_edited_to_a_finite_value_is_written(
    case: str, cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative arm: the "inf" match covers only the unchanged value, so an edit still lands."""
    _inf_file(cfg, case)
    svc = _svc(cfg, _EPIC_EGRESS)
    entries = _listed(cfg, capsys)
    path = case.split(".")
    entry = entries["IB" if case == "strict_timeout_s" else "OB"]
    target = entry
    for key in path[:-1]:
        target = target[key]
    assert target[path[-1]] == "inf"
    target[path[-1]] = 30.0
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    value: object = _listed(cfg, capsys)["IB" if case == "strict_timeout_s" else "OB"]
    for key in path:
        assert isinstance(value, dict)
        value = value[key]
    assert value == 30.0
    assert "inf" not in (cfg / "connections.toml").read_text(encoding="utf-8")


def _table_text(cfg: Path, name: str) -> str:
    """The text of connection ``name``'s table, up to the next connection header."""
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    start = text.index(f'name = "{name}"')
    ends = [i for i in (text.find("[[inbound]]", start), text.find("[[outbound]]", start)) if i > 0]
    return text[start : min(ends)] if ends else text[start:]


@pytest.mark.parametrize("case", sorted(_INF_CASES))
def test_infinite_value_clone_writes_a_bare_inf(
    case: str, cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A clone (the IDE's clone, and rename = clone + remove) appends a table with no same-named
    entry to match against. A float-typed field still gets the float back from the schema, so the
    clone carries a bare `inf`, not the string "inf" the read schema refuses (BACKLOG #5778)."""
    _inf_file(cfg, case)
    svc = _svc(cfg, _EPIC_EGRESS)
    source = "IB" if case == "strict_timeout_s" else "OB"
    entry = _listed(cfg, capsys)[source]
    entry["name"] = source + "2"
    entry["settings"]["port"] += 10
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    clone = _table_text(cfg, source + "2")
    assert f"{case.split('.')[-1]} = inf" in clone
    assert '"inf"' not in clone
    load_config(cfg)


def test_sibling_edit_in_buildup_keeps_the_untouched_inf(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (cfg / "connections.toml").write_text(
        _INF_ROUND_TRIP_FILE.format(
            inbound_extra="",
            outbound_extra="",
            outbound_tables=(
                "  [outbound.buildup]\n  max_depth = 10\n  max_oldest_seconds = inf  # age off\n"
            ),
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["OB"]
    entry["buildup"]["max_depth"] = 20
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    text = (cfg / "connections.toml").read_text(encoding="utf-8")
    assert "max_depth = 20" in text
    assert "max_oldest_seconds = inf  # age off" in text


def test_untouched_inf_in_an_edited_array_stays_a_float(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`metadata` is untyped, so the element is decoded only because the file held that float at
    that position: the operator edited limits[0], never limits[1]."""
    (cfg / "connections.toml").write_text(
        _INF_ROUND_TRIP_FILE.format(
            inbound_extra="", outbound_extra="", outbound_tables=""
        ).replace(
            "  [inbound.settings]", "  metadata = { limits = [1.0, inf] }\n  [inbound.settings]"
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["IB"]
    assert entry["metadata"]["limits"] == [1.0, "inf"]
    entry["metadata"]["limits"][0] = 2.0
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    assert load_config(cfg).inbound["IB"].metadata == {"limits": [2.0, float("inf")]}


def test_negative_infinity_round_trips_and_clones(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _INF_ROUND_TRIP_FILE.format(
        inbound_extra="strict_timeout_s = -inf  # backstop off\n",
        outbound_extra="",
        outbound_tables="",
    ).encode("utf-8")
    (cfg / "connections.toml").write_bytes(before)
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["IB"]
    assert entry["strict_timeout_s"] == "-inf"
    assert _upsert(cfg, entry, capsys, svc=svc)[0] == 0
    assert (cfg / "connections.toml").read_bytes() == before
    entry["name"] = "IB2"
    entry["settings"]["port"] = 2610
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    assert "strict_timeout_s = -inf" in _table_text(cfg, "IB2")
    assert load_config(cfg).inbound["IB2"].validation.strict_timeout_s == float("-inf")


def test_clone_decodes_env_default_and_settings_float_by_type(
    cfg: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The settings branch types by the transport factory, and an env() reference's `default` takes
    its field's type, so a clone writes both as a bare `inf` (Lander hold, item 1)."""
    monkeypatch.delenv("MEFOR_TEST_PS_UNSET", raising=False)
    out_dir = (cfg / "out").as_posix()
    (cfg / "connections.toml").write_text(
        textwrap.dedent(
            f"""\
            [[outbound]]
            name = "OB"
            transport = "file"
              [outbound.settings]
              directory = "{out_dir}"
              poll_seconds = {{ env = "MEFOR_TEST_PS_UNSET", default = inf, cast = "float" }}
              min_age_seconds = inf
            """
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, f'[egress]\nallowed_file_dirs = ["{out_dir}"]\n')
    entry = _listed(cfg, capsys)["OB"]
    assert entry["settings"]["poll_seconds"]["default"] == "inf"
    entry["name"] = "OB2"
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    clone = _table_text(cfg, "OB2")
    assert "default = inf" in clone and "min_age_seconds = inf" in clone
    assert '"inf"' not in clone
    load_config(cfg)


def test_typed_mapping_and_union_of_arrays_decode_by_element_type() -> None:
    from messagefoundry.config.connections_edit import _decode_value

    assert _decode_value({"a": "inf", "b": "x"}, (dict[str, float],), None) == {
        "a": float("inf"),
        "b": "x",
    }
    assert _decode_value({"a": "inf"}, (dict[str, str],), None) == {"a": "inf"}
    assert _decode_value(["-inf"], (list[float] | tuple[int, ...],), None) == [float("-inf")]


def test_fresh_nan_in_a_float_field_is_still_refused(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Main refused the string "nan" in a float field, and the IDE relies on that. A NaN backstop
    would never fire (`nan > 0` is false), so only "inf" / "-inf" decode by type (hold item 4)."""
    _inf_file(cfg, "strict_timeout_s")
    before = (cfg / "connections.toml").read_bytes()
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["IB"]
    entry["strict_timeout_s"] = "nan"
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 1, out
    assert "strict_timeout_s" in out
    assert (cfg / "connections.toml").read_bytes() == before


@pytest.mark.parametrize(
    "line",
    [
        "strict_timeout_s = nan  # kept\n",
        "strict_timeout_s = -nan  # kept\n",
    ],
)
def test_existing_nan_no_op_save_is_byte_identical(
    line: str, cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A NaN the file already holds decodes from its position, sign kept, and compares unchanged."""
    before = _INF_ROUND_TRIP_FILE.format(
        inbound_extra=line, outbound_extra="", outbound_tables=""
    ).encode("utf-8")
    (cfg / "connections.toml").write_bytes(before)
    svc = _svc(cfg, _EPIC_EGRESS)
    rc, out = _upsert(cfg, _listed(cfg, capsys)["IB"], capsys, svc=svc)
    assert rc == 0, out
    assert (cfg / "connections.toml").read_bytes() == before


def test_hand_written_string_inf_survives_a_no_op_save(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A float field the author spelled as the STRING "inf" (pydantic reads it) stays as written."""
    before = _INF_ROUND_TRIP_FILE.format(
        inbound_extra="",
        outbound_extra="",
        outbound_tables='  [outbound.buildup]\n  max_oldest_seconds = "inf"  # hand\n',
    ).encode("utf-8")
    (cfg / "connections.toml").write_bytes(before)
    svc = _svc(cfg, _EPIC_EGRESS)
    rc, out = _upsert(cfg, _listed(cfg, capsys)["OB"], capsys, svc=svc)
    assert rc == 0, out
    assert (cfg / "connections.toml").read_bytes() == before


@pytest.mark.parametrize(
    ("edit", "expected"),
    [
        (lambda limits: limits.insert(0, 0.5), [0.5, 1.0, float("inf")]),
        (lambda limits: limits.pop(0), [float("inf")]),
    ],
    ids=["insert", "delete"],
)
def test_untouched_inf_survives_an_array_shift(
    edit: object, expected: list[float], cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Array elements match the file's floats by value, so a shift keeps the untouched inf."""
    (cfg / "connections.toml").write_text(
        _INF_ROUND_TRIP_FILE.format(
            inbound_extra="", outbound_extra="", outbound_tables=""
        ).replace(
            "  [inbound.settings]", "  metadata = { limits = [1.0, inf] }\n  [inbound.settings]"
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["IB"]
    assert callable(edit)
    edit(entry["metadata"]["limits"])
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    assert load_config(cfg).inbound["IB"].metadata == {"limits": expected}


def test_policy_models_cover_every_typed_sub_table() -> None:
    """Drift guard: a new pydantic-read sub-table must be added to _POLICY_MODELS, or its float
    fields would not decode on a clone. `settings` is typed elsewhere, `metadata` not at all."""
    from messagefoundry.config import connections_edit

    assert set(connections_edit._POLICY_MODELS) == set(connections_edit._SUB_TABLES) - {
        "settings",
        "metadata",
    }


def test_a_string_field_holding_inf_stays_a_string(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control arm: a string-typed field (`cleartext_reason`) and an untyped one whose file
    value is already a string (`metadata.tag`) are never decoded, on a re-save or on a clone."""
    (cfg / "connections.toml").write_text(
        _INF_ROUND_TRIP_FILE.format(
            inbound_extra="", outbound_extra="", outbound_tables=""
        ).replace(
            'cleartext_reason = "legacy partner has no MLLP-over-TLS listener"',
            'cleartext_reason = "inf"\nmetadata = { tag = "inf" }',
        ),
        encoding="utf-8",
    )
    svc = _svc(cfg, _EPIC_EGRESS)
    entry = _listed(cfg, capsys)["OB"]
    assert _upsert(cfg, entry, capsys, svc=svc)[0] == 0
    entry["name"] = "OB2"
    rc, out = _upsert(cfg, entry, capsys, svc=svc)
    assert rc == 0, out
    reg = load_config(cfg)
    for name in ("OB", "OB2"):
        assert reg.outbound[name].cleartext_reason == "inf"
        assert reg.outbound[name].metadata == {"tag": "inf"}


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


def test_cli_upsert_reports_connection_json_nested_past_the_decoder(
    cfg: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A `RecursionError` is a `RuntimeError`, so the `except json.JSONDecodeError` arm this
    subcommand used to carry structurally could not reach one, and deeply nested `--data` escaped
    uncaught (BACKLOG #1855).

    The conversion is scoped by TYPE, to the `json.loads` call alone, NOT to this subcommand's wide
    `try`: that `try` also wraps `upsert_connection`, `remove_connection` and the build-check
    callback, and a `RecursionError` raised by any of those is not an `_OperatorJsonError`, so the
    arm below still does not blame the operator's input for it. Pinned by
    `test_cli_upsert_does_not_report_a_downstream_recursion_error_as_bad_input` below.

    Why, and why the trigger below is manufactured rather than real nesting: `_load_operator_json`
    in `messagefoundry/cli_common.py`. The type facts are pinned once, by the anchor test
    `tests/test_security_cli.py::test_cli_set_reports_security_json_nested_past_the_decoder`.

    RED when: `_load_operator_json`'s `except RecursionError` arm, or `_connection`'s
    `except _OperatorJsonError` arm, is dropped."""

    def _raise_recursion(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("simulated deep nesting")

    monkeypatch.setattr("messagefoundry.cli_common.json.loads", _raise_recursion)
    rc = main(["connection", "upsert", "--config", str(cfg), "--data", "[]", "--json"])
    out = capsys.readouterr().out
    monkeypatch.undo()  # restore json.loads before parsing the captured payload with it

    assert rc == 1
    assert json.loads(out)["error"].startswith("connection JSON is nested too deeply to parse")
    assert not (cfg / "connections.toml").exists()  # nothing was written


def test_cli_upsert_does_not_report_a_downstream_recursion_error_as_bad_input(
    cfg: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The converse of the test above, and the property that lets ONE arm serve a wide `try`: the
    conversion is scoped by TYPE, so a `RecursionError` raised downstream of the decode is still not
    reported as invalid operator JSON.

    `_connection`'s single `except _OperatorJsonError` arm sits on a `try` that also wraps
    `upsert_connection` and the build-check callback. It is safe there only because
    `_load_operator_json` wraps `json.loads` ALONE -- nothing else in the block can produce an
    `_OperatorJsonError`. So drive `upsert_connection` itself into a `RecursionError` on input that
    decoded fine: it must reach `main`'s dispatch-level floor rather than be blamed on the operator's
    `--data`. Since BACKLOG #1863 that floor returns 1 with a JSON error naming the exception type,
    so the discriminator is the error TEXT, not whether `main` raises.

    RED when: the conversion moves out to the subcommand's wide `try` (an `except RecursionError`
    there), or `_load_operator_json` grows to wrap more than the decode. Either turns this into an
    exit 1 reporting "connection JSON is nested too deeply to parse" about a payload that parsed."""
    from messagefoundry.config import connections_edit

    def _raise_recursion(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("raised by upsert_connection, not by the decode")

    monkeypatch.setattr(connections_edit, "upsert_connection", _raise_recursion)
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    rc = main(["connection", "upsert", "--config", str(cfg), "--data", json.dumps(obj), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]

    assert rc == 1
    assert error.startswith("RecursionError: raised by upsert_connection"), error
    assert "nested too deeply" not in error, "a downstream fault was blamed on the operator's input"


_PARTNER_OUTBOUND = {
    "direction": "outbound",
    "name": "OB",
    "transport": "mllp",
    "settings": {"host": "epic.example", "port": 2700},
    "cleartext_accepted": True,
    "cleartext_reason": "legacy partner has no MLLP-over-TLS listener",
}


@pytest.fixture
def _no_egress_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A shell exporting an [egress] or [security] override would change what these tests see."""
    import os

    for key in list(os.environ):
        if key.upper().startswith(("MEFOR_EGRESS_", "MEFOR_SECURITY_")):
            monkeypatch.delenv(key)


@pytest.mark.usefixtures("_no_egress_env")
def test_an_unlisted_outbound_edit_without_a_service_config_names_where_the_list_goes(
    cfg: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A `connection upsert` may name no --service-config: a hand-run one, or the IDE's when its
    # serviceConfig setting is unset, here with no settings file (vault BACKLOG #2908). Under the
    # deny default (vault BACKLOG #2605) an unlisted outbound is refused, and the refusal must say
    # which flag and which [egress] list fix it, rather than leave the analyst guessing which file
    # was read.
    monkeypatch.chdir(cfg)  # no messagefoundry.toml here, so no settings file is found
    rc, out = _upsert(cfg, _PARTNER_OUTBOUND, capsys)
    error = json.loads(out)["error"]
    assert rc != 0
    assert "block_unlisted_outbound" in error
    assert "--service-config" in error and "[egress] allowed_*" in error
    assert "with no instance settings file" in error
    assert not (cfg / "connections.toml").exists()  # rolled back, nothing persisted


@pytest.mark.usefixtures("_no_egress_env")
def test_the_hint_names_the_working_directory_file_it_read(
    cfg: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # load_settings falls back to ./messagefoundry.toml. When that file exists the hint must name
    # it, not claim that no settings file was read.
    monkeypatch.chdir(cfg)
    (cfg / "messagefoundry.toml").write_text("", encoding="utf-8")
    rc, out = _upsert(cfg, _PARTNER_OUTBOUND, capsys)
    error = json.loads(out)["error"]
    assert rc != 0
    assert "--service-config" in error
    assert "the settings file in the working directory" in error
    assert "with no instance settings file" not in error


@pytest.mark.usefixtures("_no_egress_env")
def test_the_service_config_hint_names_the_file_that_was_given(
    cfg: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The same refusal with a service file named does not ask for one, but still names the file it
    # read and the list to change there: the IDE names its setting's file (vault BACKLOG #2908).
    svc = _svc(cfg)
    rc, out = _upsert(cfg, _PARTNER_OUTBOUND, capsys, svc=svc)
    error = json.loads(out)["error"]
    assert rc != 0
    assert "block_unlisted_outbound" in error
    assert "No --service-config was given" not in error
    assert f"checked against {svc.absolute()}, the file --service-config named" in error
    assert "[egress] allowed_*" in error


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_service_config_is_refused_by_name(
    cfg: Path, capsys: pytest.CaptureFixture[str], blank: str
) -> None:
    # The IDE passes a blank messagefoundry.serviceConfig setting through rather than drop it
    # (vault BACKLOG #2908). An empty name would otherwise reach the open as the working directory
    # and fail with an OS error that does not say the name was blank.
    data = json.dumps(_PARTNER_OUTBOUND)
    rc = main(
        ["connection", "upsert", "--config", str(cfg), "--data", data, "--json"]
        + ["--service-config", blank]
    )
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc != 0
    assert error.startswith("--service-config is blank")
    assert not (cfg / "connections.toml").exists()
