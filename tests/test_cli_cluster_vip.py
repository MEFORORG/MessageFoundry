# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``messagefoundry cluster-vip`` -- the JSON projection of ``[cluster.vip]`` (BACKLOG #1523).

WHY THE PROJECTION EXISTS, because it decides what these tests have to prove.
``scripts/service/install-net-helper.ps1`` writes the helper's ``address``, ``interface`` and
``mask`` into ``mefor-net-helper.conf``, and the helper then refuses every request naming other
values (ADR 0056). PowerShell has no TOML parser, and adding one would make the installer a SECOND
DEFINITION of the block rather than a second reader of it. So the installer shells back into the
engine and parses one line of JSON, and the guards below are on the three ways that projection could
quietly stop being the same values the engine loaded:

1. it must actually READ the file -- a present block and an absent one must not project the same
   thing (``test_present_and_absent_blocks_do_not_project_the_same_payload``, the positive control
   for every other case here: a projection exercised only against a config that HAS the block cannot
   tell you what it does with one that does not);
2. it must project the RESOLVED ``mask``, not the spelling -- ``prefix = 24`` and
   ``netmask = "255.255.255.0"`` are one wire value, and the ``.conf`` takes only that one;
3. a config that will not load must be an ERROR the caller can see, not an empty or half-filled
   read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main

# Same shape as tests/test_settings.py's VIP fixtures: [cluster.vip] needs [cluster].enabled, which
# needs a server-DB store.
_PG = '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
_VIP_ON = _PG + "[cluster]\nenabled = true\n[cluster.vip]\nenabled = true\n"
_VIP_USABLE = 'address = "192.0.2.50"\ninterface = "Ethernet0"\n'


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, object]]:
    """Run the subcommand and parse its stdout, which is the installer's whole contract with it."""
    code = main(["cluster-vip", *argv])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    return code, parsed


def test_present_and_absent_blocks_do_not_project_the_same_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE CONTROL. Two configs, one with the block and one without, through the same code path.

    A projection that ignored its ``--service-config`` -- read a stale default, or returned model
    defaults -- would pass every assertion about the enabled case below and still be useless to the
    installer. This is the only test here that would catch that, so it asserts the difference itself
    rather than inferring it from the two halves.
    """
    with_block = _write(tmp_path / "with.toml", _VIP_ON + _VIP_USABLE + "prefix = 24\n")
    without_block = _write(tmp_path / "without.toml", _PG)

    on_code, on = _run(capsys, "--service-config", str(with_block), "--json")
    off_code, off = _run(capsys, "--service-config", str(without_block), "--json")

    assert (on_code, off_code) == (0, 0)
    assert on != off
    assert on["enabled"] is True
    assert (on["address"], on["interface"], on["mask"]) == (
        "192.0.2.50",
        "Ethernet0",
        "255.255.255.0",
    )
    assert off["enabled"] is False
    assert (off["address"], off["interface"], off["mask"]) == (None, None, None)


@pytest.mark.parametrize(
    ("mask_lines", "wire_mask"),
    [
        ("prefix = 24\n", "255.255.255.0"),
        ('netmask = "255.255.255.0"\n', "255.255.255.0"),
        ("prefix = 25\n", "255.255.255.128"),
    ],
)
def test_either_mask_spelling_projects_the_one_wire_mask(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mask_lines: str, wire_mask: str
) -> None:
    # The installer writes `mask` into the .conf verbatim, and the helper compares the bind request
    # against it byte for byte. Projecting `prefix` would hand it a value it cannot use.
    cfg = _write(tmp_path / "messagefoundry.toml", _VIP_ON + _VIP_USABLE + mask_lines)
    code, payload = _run(capsys, "--service-config", str(cfg), "--json")
    assert code == 0
    assert payload["mask"] == wire_mask
    assert "prefix" not in payload and "netmask" not in payload


def test_the_whole_block_is_projected_including_the_fields_no_installer_reads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``gratuitous_arp`` and ``release_grace_seconds`` are in the payload and pinned here.

    No installer reads either one; they are there because the subcommand projects the block, and an
    operator reading the human form should see the block. That makes them two fields in a
    machine-parsed contract with no other reader, which is a liability -- so this is their reader. A
    rename or a default change on ``ClusterVipSettings`` turns this red instead of silently changing
    what the CLI emits.
    """
    cfg = _write(tmp_path / "messagefoundry.toml", _VIP_ON + _VIP_USABLE + "prefix = 24\n")
    _, on = _run(capsys, "--service-config", str(cfg), "--json")
    assert on["gratuitous_arp"] is True
    assert on["release_grace_seconds"] == 2.0
    assert set(on) == {
        "enabled",
        "cluster_enabled",
        "address",
        "interface",
        "mask",
        "gratuitous_arp",
        "release_grace_seconds",
    }


def test_off_block_reports_which_switch_is_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # [cluster.vip].enabled requires [cluster].enabled, so "the VIP is off" is two switches. An
    # installer that reported only the inner one would send an operator to the wrong line.
    cfg = _write(tmp_path / "messagefoundry.toml", _PG + "[cluster]\nenabled = true\n")
    code, payload = _run(capsys, "--service-config", str(cfg), "--json")
    assert code == 0
    assert payload["enabled"] is False
    assert payload["cluster_enabled"] is True


def test_switched_off_block_projects_its_unvalidated_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A disabled block is a no-op the loader never validates, and this projects it as it stands.

    Asserted rather than left implicit: the installer must not read a disabled block's address as
    installable, and the only thing that stops it is its own check of ``enabled`` -- not a refusal
    here. A projection that silently blanked these fields would hide the operator's half-finished
    block from the installer's own refusal message.
    """
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        '[cluster.vip]\nenabled = false\naddress = "not-an-address"\ninterface = "Ethernet0"\n',
    )
    code, payload = _run(capsys, "--service-config", str(cfg), "--json")
    assert code == 0
    assert payload["enabled"] is False
    assert payload["address"] == "not-an-address"
    assert payload["mask"] is None


def test_missing_config_is_an_error_line_and_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Stdout stays JSON on the failure path (the `ai-policy` shape), so the caller's ConvertFrom-Json
    # never sees an empty string it would have to guess about.
    code, payload = _run(capsys, "--service-config", str(tmp_path / "absent.toml"), "--json")
    assert code == 2
    assert "absent.toml" in str(payload["error"])
    assert "address" not in payload


def test_a_directory_at_service_config_is_an_error_line_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An easy typo: the config DIRECTORY instead of the file inside it. Path.exists() is True and the
    # open raises IsADirectoryError, which is an OSError and not a FileNotFoundError -- so without
    # OSError in the catch the traceback goes to stderr, stdout is empty, and the installer reports
    # "printed nothing" instead of the reason.
    code, payload = _run(capsys, "--service-config", str(tmp_path), "--json")
    assert code == 2
    assert "error" in payload


def test_enabled_but_unusable_block_is_an_error_not_a_half_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An enabled block with no mask form is refused at LOAD (ADR 0056 AC-8). The installer must see
    # that refusal, not a payload with `mask: null` it would happily write into the .conf.
    cfg = _write(tmp_path / "messagefoundry.toml", _VIP_ON + _VIP_USABLE)
    code, payload = _run(capsys, "--service-config", str(cfg), "--json")
    assert code == 2
    assert "prefix or netmask" in str(payload["error"])


def test_the_no_controller_warning_goes_to_stderr_not_into_the_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The loader's "this build has no VIP controller" WARNING must not land in the JSON.

    It fires on exactly the config the installer is run against -- a switched-on block -- so a copy
    on stdout would break every real install while passing every test that did not look. What keeps
    it off is ``main``'s ``configure_stderr_logging()`` for any ``--json`` subcommand (BACKLOG
    #1489), which this one inherits by spelling its flag ``--json``; this pins that it actually
    applies here. The installer relies on it from the other side: it reads stdout and leaves stderr
    alone, because a ``2>&1`` merge would put the warning in front of the payload AND, on Windows
    PowerShell 5.1, can turn it into a terminating error.

    Both halves are asserted, and the stderr half is the control: a run where the warning simply did
    not fire would satisfy a stdout-only assertion and prove nothing.
    """
    cfg = _write(tmp_path / "messagefoundry.toml", _VIP_ON + _VIP_USABLE + "prefix = 24\n")
    assert main(["cluster-vip", "--service-config", str(cfg), "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["address"] == "192.0.2.50"
    assert captured.out.count("\n") == 1
    assert "no engine-managed VIP controller" in captured.err


def test_without_json_the_output_is_indented_and_still_parses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --json is the compact spelling the installer asks for; the bare form is the one an operator
    # reads. Both are JSON, which is what lets the script's error handling be the same on both.
    cfg = _write(tmp_path / "messagefoundry.toml", _VIP_ON + _VIP_USABLE + "prefix = 24\n")
    assert main(["cluster-vip", "--service-config", str(cfg)]) == 0
    human = capsys.readouterr().out
    assert "\n  " in human
    assert json.loads(human)["mask"] == "255.255.255.0"
