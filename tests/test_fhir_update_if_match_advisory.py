# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The path-form FHIR update with no ``If-Match`` advisory (vault BACKLOG #2570).

A plain ``interaction="update"`` sends ``PUT {base}/{ResourceType}/{id}`` with no ``If-Match`` header.
A server that requires the header on update would refuse it, so on a first deployment against such a
server every update would dead-letter, with nothing at load saying why.

The reader names what a connection DECLARES. It cannot see a header a Handler stamps, and nothing in a
connection names the server's vendor, so the line is advisory and has to say both limits. Each control
below is a way of declaring the header that must keep the line quiet.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import redaction
from messagefoundry.checks import CheckResult, run_checks
from messagefoundry.config.wiring import load_config, path_form_fhir_updates_without_if_match

_BASE = "https://fhir.example.invalid/fhir"
_HEADER = f"""
from messagefoundry import FHIR, env, outbound

_BASE = "{_BASE}"
"""


def _config(tmp_path: Path, body: str) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir(parents=True)
    (cfg / "feed.py").write_text(_HEADER + body, encoding="utf-8")
    return cfg


def _read(tmp_path: Path, body: str) -> list[tuple[str, str]]:
    return path_form_fhir_updates_without_if_match(load_config(_config(tmp_path, body)))


def _line(cfg: Path) -> CheckResult:
    [r] = [r for r in run_checks(cfg, run_lint=False).results if r.name == "fhir-update-if-match"]
    return r


_PLAIN = 'outbound("OB_PLAIN", FHIR(url=_BASE, interaction="update", update_url_form="path"))\n'


def test_a_plain_path_form_update_is_named(tmp_path: Path) -> None:
    assert _read(tmp_path, _PLAIN) == [
        ("OB_PLAIN", "dynamic_headers is off, so no Handler can add one")
    ]


def test_the_note_says_a_handler_may_stamp_the_header(tmp_path: Path) -> None:
    # A Handler can stamp If-Match per message, and no load-time reader can know whether it does.
    # So the connection is still named, and the note says why that may be a false alarm.
    body = (
        'outbound("OB_DYN", FHIR(url=_BASE, interaction="update", update_url_form="path",\n'
        "         dynamic_headers=True))\n"
    )
    assert _read(tmp_path, body) == [
        ("OB_DYN", "dynamic_headers is on, so a Handler may stamp If-Match per message")
    ]


@pytest.mark.parametrize(
    "declared",
    [
        'conditional="if-match"',  # THE CONTROL: the connector derives the ETag itself
        'interaction="update", headers={"If-Match": "*"}',
        'interaction="update", headers={"if-match": "*"}',  # any letter case
        'interaction="update", headers={"IF-MATCH": "*"}',
        'interaction="update", headers={"X-Trace": "t", "If-match": "*"}',
    ],
)
def test_a_declared_if_match_keeps_the_line_quiet(tmp_path: Path, declared: str) -> None:
    body = f'outbound("OB", FHIR(url=_BASE, {declared}, update_url_form="path"))\n'
    assert _read(tmp_path, body) == []


def test_another_header_is_not_an_if_match(tmp_path: Path) -> None:
    body = (
        'outbound("OB", FHIR(url=_BASE, interaction="update", update_url_form="path",\n'
        '         headers={"If-None-Match": "*", "X-If-Match": "*"}))\n'
    )
    assert [name for name, _ in _read(tmp_path, body)] == ["OB"]


def test_only_the_path_form_is_read(tmp_path: Path) -> None:
    # The default form wraps the update in a transaction Bundle. A server with no transaction
    # interaction refuses that form outright, so this line has nothing to add there.
    body = (
        'outbound("OB_TXN_FORM", FHIR(url=_BASE, interaction="update"))\n'
        'outbound("OB_CREATE", FHIR(url=_BASE, interaction="create"))\n'
    )
    assert _read(tmp_path, body) == []


def test_an_env_headers_table_is_named_with_the_reason(tmp_path: Path) -> None:
    body = (
        'outbound("OB_ENV", FHIR(url=_BASE, interaction="update", update_url_form="path",\n'
        '         headers=env("all_headers")))\n'
    )
    [(name, note)] = _read(tmp_path, body)
    assert name == "OB_ENV"
    assert note.startswith("its headers are an env() reference, which check does not resolve; ")


def test_a_literal_header_named_env_is_not_an_env_reference(tmp_path: Path) -> None:
    # `{"env": ...}` is the shape of a connections.toml reference. Here it is a real header table.
    body = (
        'outbound("OB", FHIR(url=_BASE, interaction="update", update_url_form="path",\n'
        '         headers={"env": "prod"}))\n'
    )
    assert _read(tmp_path, body) == [("OB", "dynamic_headers is off, so no Handler can add one")]


def test_the_set_is_a_subset_of_the_path_form_reader(tmp_path: Path) -> None:
    from messagefoundry.config.wiring import path_form_fhir_updates

    body = _PLAIN + (
        'outbound("OB_ETAG", FHIR(url=_BASE, conditional="if-match", update_url_form="path"))\n'
        'outbound("OB_A_PLAIN", FHIR(url=_BASE, interaction="update", update_url_form="path"))\n'
    )
    registry = load_config(_config(tmp_path, body))
    named = [name for name, _ in path_form_fhir_updates_without_if_match(registry)]
    assert named == ["OB_A_PLAIN", "OB_PLAIN"]  # sorted, as the path-form reader is
    assert set(named) < set(path_form_fhir_updates(registry))


def test_check_names_the_connection_and_says_both_limits(tmp_path: Path) -> None:
    body = _PLAIN + (
        'outbound("OB_ETAG", FHIR(url=_BASE, conditional="if-match", update_url_form="path"))\n'
    )
    r = _line(_config(tmp_path, body))
    assert r.ok and not r.required and not r.skipped and not r.blocking
    assert r.detail.startswith(
        "1 path-form FHIR update(s) have no If-Match that check can read: OB_PLAIN ("
    )
    assert "OB_ETAG" not in r.detail
    assert "conditional='if-match', which needs meta.versionId" in r.detail
    assert "a static If-Match in headers" in r.detail
    # The two limits that keep it advisory, in the line itself.
    assert "cannot tell which server a connection points at" in r.detail
    assert "or see a header a Handler stamps" in r.detail
    # The vendor is still named, in words the PHI name heuristic does not scrub.
    assert "Oracle documents that requirement" in r.detail
    assert "its Health platform (Millennium)" in r.detail
    assert redaction._NAME_RUN.findall(r.detail) == []


def test_check_says_none_out_loud(tmp_path: Path) -> None:
    body = 'outbound("OB", FHIR(url=_BASE, conditional="if-match", update_url_form="path"))\n'
    r = _line(_config(tmp_path, body))
    assert r.ok and not r.skipped
    assert r.detail == "every path-form FHIR update declares an If-Match that check can read"


def test_check_says_there_is_nothing_to_read_when_no_update_takes_the_path_form(
    tmp_path: Path,
) -> None:
    # "None exist" is a different line from "all declare one".
    r = _line(_config(tmp_path, 'outbound("OB", FHIR(url=_BASE, interaction="update"))\n'))
    assert r.ok and not r.skipped
    assert r.detail == (
        "no FHIR connection sets update_url_form='path', so there is no update to read"
    )


def test_an_env_dynamic_headers_is_not_called_on(tmp_path: Path) -> None:
    body = (
        'outbound("OB", FHIR(url=_BASE, interaction="update", update_url_form="path",\n'
        '         dynamic_headers=env("dyn")))\n'
    )
    assert _read(tmp_path, body) == [
        ("OB", "dynamic_headers is an env() reference, which check does not resolve")
    ]


def test_check_skips_rather_than_reporting_clean_on_an_unloadable_config(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "broken.py").write_text("this is not python(", encoding="utf-8")
    r = _line(cfg)
    assert r.skipped and r.ok and not r.required and "config did not load" in r.detail
