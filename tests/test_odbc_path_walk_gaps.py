# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Gaps in the generic ODBC remote-path walk that engine PR 2671 added (vault BACKLOG #5197).

Each test names the row's item it pins, and each was red on the code before the fix. The walk
takes its file system as injected callables (``probe``, ``drive_type``, ``drive_target``, ``cwd``)
and reads paths with ``ntpath``, so every test here runs on any platform. Every fix moves a verdict
toward ``None`` (could not clear) or ``True`` (leads off the host), never toward ``False``.

Synthetic paths and host names only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import anchor_path
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import DIRECTORY, FILE, LINK, windows_chain
from messagefoundry.transports import database

_FIXED = 3  # GetDriveTypeW: a fixed disk
_SHARE = r"\\files.test\share"


def _probe(
    links: Mapping[str, str] | None = None, failing: Mapping[str, OSError] | None = None
) -> Callable[[str], tuple[str, str | None]]:
    """A file system where every name is a folder or a ``.pem`` file, except the ``links`` (path to
    stored target) and the ``failing`` paths (path to the error its probe raises)."""
    links = {k.lower(): v for k, v in (links or {}).items()}
    failing = {k.lower(): v for k, v in (failing or {}).items()}

    def probe(part: str) -> tuple[str, str | None]:
        key = part.lower()
        if key in failing:
            raise failing[key]
        if key in links:
            return LINK, links[key]
        return (FILE if key.endswith(".pem") else DIRECTORY), None

    return probe


def _no_cwd() -> str:
    raise AssertionError("the walk must not read the process working directory here")


def _walk(
    path: str,
    links: Mapping[str, str] | None = None,
    *,
    substs: Mapping[str, str] | None = None,
    failing: Mapping[str, OSError] | None = None,
    cwd: str | Callable[[], str] = r"C:\work",
) -> bool | None:
    return database._windows_path_verdict(
        path,
        probe=_probe(links, failing),
        drive_type=lambda _root: _FIXED,
        drive_target=lambda drive: (substs or {}).get(drive.upper()),
        cwd=cwd,
    )


# --- item 9: a rooted, driveless link target -----------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        r"\RPC Control\certlink",  # an object directory an unprivileged account can add links to
        r"\DosDevices\UNC\files.test\share\ca.pem",
        r"\Sessions\1\DosDevices\0000-1\UNC\files.test\share\ca.pem",
        "/Device/Mup/files.test/share/ca.pem",  # forward separators
        r"\other\ca.pem",  # even one that reads as a folder on the link's drive
    ],
)
def test_item_9_a_rooted_driveless_link_target_is_not_cleared(target: str) -> None:
    """Any rooted link target with no drive is unclear, whatever its first name: a list of object
    roots always trails the object namespace. Red with the old name list, which cleared each of
    these as a folder on the link's drive."""
    assert _walk(r"C:\certs\ca.pem", {r"C:\certs\ca.pem": target}) is None


def test_item_9_a_link_to_a_drive_letter_path_is_still_walked() -> None:
    """The control: a link whose target carries its drive is walked as before."""
    assert _walk(r"C:\certs\ca.pem", {r"C:\certs\ca.pem": r"C:\real\ca.pem"}) is False
    assert _walk(r"C:\certs\ca.pem", {r"C:\certs\ca.pem": r"\\?\C:\real\ca.pem"}) is False


# --- item 10: a component ending in a space or a dot ---------------------------------------------


@pytest.mark.parametrize(
    ("path", "links"),
    [
        (r"C:\certs \ca.pem", {}),
        (r"C:\certs.\ca.pem", {}),
        (r"C:\certs\ca.pem.", {}),
        (r"C:\certs\ca.pem", {r"C:\certs\ca.pem": r"C:\other \ca.pem"}),  # inside a link target
    ],
)
def test_item_10_a_component_ending_in_a_space_or_dot_is_not_cleared(
    path: str, links: dict[str, str]
) -> None:
    """Win32 strips a trailing space or dot from a name, so the probe reads another object than
    the text names. Red with the walk probing such a name as written."""
    assert _walk(path, links) is None


def test_item_10_dot_and_dot_dot_are_still_walked() -> None:
    """The control: ``.`` and ``..`` are collapsed before the walk, as Win32 collapses them."""
    assert _walk(r"C:\certs\.\sub\..\ca.pem") is False


# --- items 11 and 14: a subst drive onto a share -------------------------------------------------


def test_item_14_the_query_answer_is_kept_whole() -> None:
    """``QueryDosDeviceW`` answers ``\\??\\UNC\\host\\share`` for a drive substituted onto a share.
    Four characters stripped by hand left ``UNC\\host\\share``, which the walk read as a path with
    no drive. Both readers now keep the whole answer. Red: the helper did not exist."""
    assert anchor_path.subst_target("\\??\\UNC\\files.test\\share") == (
        "\\??\\UNC\\files.test\\share"
    )
    assert anchor_path.subst_target("\\??\\C:\\certs") == "\\??\\C:\\certs"
    assert anchor_path.subst_target("\\Device\\HarddiskVolume3") is None
    assert anchor_path.subst_target("\\Device\\LanmanRedirector\\;Z:0\\files.test\\s") is None


@pytest.mark.parametrize("answer", ["\\??\\UNC\\files.test\\share", "\\??\\unc\\files.test\\s"])
def test_item_11_a_subst_drive_onto_a_share_leads_off_the_host(answer: str) -> None:
    """A subst drive whose target is a share leads off the host, so the verdict is ``True``, not
    "could not tell". Red: the walk answered ``None``, as a share it could not read."""
    assert _walk(r"S:\ca.pem", substs={"S:": answer}) is True


def test_item_11_a_subst_drive_onto_a_local_folder_is_still_walked() -> None:
    """The control: the whole answer for a local folder is walked as the folder."""
    assert _walk(r"S:\ca.pem", substs={"S:": "\\??\\C:\\certs"}) is False
    assert _walk(r"S:\ca.pem", {r"C:\certs": _SHARE}, substs={"S:": "\\??\\C:\\certs"}) is True


# --- item 12: a drive-relative spelling ----------------------------------------------------------


@pytest.mark.parametrize("path", [r"C:ca.pem", r"D:link\ca.pem", "C:", r"\\?\C:ca.pem"])
def test_item_12_a_drive_relative_spelling_is_not_cleared(path: str) -> None:
    """``X:`` with no separator after it is read from that drive's own working directory, which
    is not the process's. The walk does not guess it and does not read the process working
    directory. Red: the old walk joined the spelling to the process working directory."""
    assert _walk(path, cwd=_no_cwd) is None


def test_item_12_a_drive_relative_link_or_subst_target_is_not_cleared() -> None:
    assert _walk(r"C:\certs\ca.pem", {r"C:\certs\ca.pem": "C:other.pem"}) is None
    assert _walk(r"S:\ca.pem", substs={"S:": "\\??\\C:certs"}) is None


def test_item_12_a_relative_or_rooted_spelling_is_still_walked() -> None:
    """The control: a plain relative spelling still joins the working directory."""
    assert _walk("ca.pem") is False
    assert _walk(r"C:\ca.pem", cwd=_no_cwd) is False


def test_items_9_10_and_12_reach_the_anchor_walk_too() -> None:
    """``windows_chain`` is shared with the trust-anchor walk, so it answers a cause there too,
    rather than reading a rooted link target as a folder on the link's drive."""
    _chain, cause = windows_chain("C:ca.pem", _no_cwd, _probe())
    assert cause is not None
    _chain, cause = windows_chain(r"C:\certs \ca.pem", r"C:\work", _probe())
    assert cause is not None
    links = {r"C:\certs": r"\RPC Control\certlink"}
    _chain, cause = windows_chain(r"C:\certs\ca.pem", r"C:\work", _probe(links))
    assert cause is not None and "phi" not in cause.kind


# --- item 15: a falsy value that is not text -----------------------------------------------------


def test_item_15_a_falsy_value_is_judged_as_the_text_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The build sends ``0`` as ``"0"``, a relative path the driver opens. Red: truthiness left it
    unwalked, unrefused and unread."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: True)
    assert dict(database.file_keyword_verdicts(0)) == {"0": True}
    assert database.names_another_host(0) is True
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    assert database.driver_file_spellings(0) == ("0",)
    read: list[str] = []

    def reading(path: str, _limit: int) -> bytes:
        read.append(path)
        return b"-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(database, "read_if_regular", reading)
    database._refuse_encrypted_driver_ca({"sslca": 0}, connection="OB_DB_GEN")
    assert read == ["0"]


def test_item_15_the_lane_check_counts_a_falsy_value() -> None:
    settings = {"dialect": "generic", "odbc_params": {"sslca": 0}}
    assert ta._names_lane_sslca(settings) is True
    assert ta._names_lane_sslca({"dialect": "generic", "odbc_params": {"sslca": ""}}) is False


# --- item 8: a padded value on the lane check ----------------------------------------------------


def test_item_8_the_lane_check_refuses_a_padded_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The build refuses a padded value, so the lane check does too, before it walks or stats
    either spelling. Red: the lane check walked both spellings and statted the padded one."""

    def never(_path: str) -> bool | None:
        raise AssertionError("a padded value must be refused before it is walked")

    monkeypatch.setattr(database, "_path_verdict", never)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"synthetic")
    settings: dict[str, Any] = {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", "SSLCA": f"{ca} "},
    }
    with pytest.raises(ValueError, match="start or end with a space") as refused:
        ta.database_ca_anchor_spec("OB_DB_GEN", settings)
    assert str(tmp_path) not in str(refused.value)


# --- item 22: the cause reaches the operator without the path ------------------------------------


@pytest.mark.parametrize(
    ("walk", "kind"),
    [
        (
            lambda: _walk(r"C:\phi-name\ca.pem", failing={r"C:\phi-name": PermissionError(5, "x")}),
            "could not be read",
        ),
        (
            lambda: _walk(r"C:\phi-name\ca.pem", {r"C:\phi-name": r"\RPC Control\l"}),
            "rooted path with no drive",
        ),
        (lambda: _walk(r"C:\phi-name \ca.pem"), "ends in a space or a dot"),
    ],
)
def test_item_22_the_cause_is_warned_without_the_path(
    caplog: pytest.LogCaptureFixture, walk: Callable[[], bool | None], kind: str
) -> None:
    """The not-cleared cause reaches a WARNING as a path-free class, and the path stays at DEBUG.
    Red: the cause went only to DEBUG, so the operator saw a refusal and no reason."""
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    assert walk() is None
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warned and all("phi-name" not in m for m in warned)
    assert any(kind in m for m in warned)
    debugged = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("phi-name" in m for m in debugged)


def test_item_22_a_walk_cause_carries_a_path_free_kind() -> None:
    _chain, cause = windows_chain(
        r"C:\phi-name\ca.pem", r"C:\work", _probe(failing={r"C:\phi-name": PermissionError(5, "x")})
    )
    assert isinstance(cause, anchor_path.WalkCause)
    assert "phi-name" in cause and "phi-name" not in cause.kind
