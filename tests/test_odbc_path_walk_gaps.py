# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Gaps in the generic ODBC remote-path walk that engine PR 2671 added (vault BACKLOG #5197).

Each test names the row's item it pins. Each was red on the code before its fix, except the ones
whose docstring calls them a control. The walk takes its file system as injected callables
(``probe``, ``drive_type``, ``drive_target``, ``cwd``) and reads paths with ``ntpath``, so the
tests run on any platform, apart from the real-reader halves of findings 4, 5 and 9. Every fix
moves a verdict toward ``None`` (could not clear) or ``True`` (leads off the host), with one
exception: turn 2's PR 2738 finding 1 moves a subst drive onto a bare drive (``\\??\\C:``), which
the walk refused for a cause that was not there, to ``False``, where the walk now reads the path
it stands for.

Synthetic paths and host names only.
"""

from __future__ import annotations

import copy
import logging
import os
import pickle
import re
import sys
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
    assert cause is not None and "certs" in cause and "certs" not in cause.kind


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


# --- review of #5197: spellings the walk read as other objects ----------------------------------


def test_review_a_stream_name_after_a_link_is_not_cleared() -> None:
    """``ntpath.join`` restarts at a remaining ``D:ca.pem``, so after a link the walk read
    ``D:\\ca.pem`` where Windows opens a stream of ``C:\\real\\D``. Red: cleared as ``False``."""
    links = {r"C:\certs\lnk": r"C:\real"}
    assert _walk(r"C:\certs\lnk\D:ca.pem", links) is None
    _chain, cause = windows_chain(r"C:\certs\lnk\D:ca.pem", r"C:\work", _probe(links))
    assert cause is not None


@pytest.mark.parametrize(
    ("path", "links", "substs"),
    [
        # A subst drive behind a forward-slash device prefix skipped the subst lookup: was False.
        (r"C:\certs\ca.pem", {r"C:\certs\ca.pem": "//?/S:/ca.pem"}, {"S:": r"\??\UNC\f.test\s"}),
        ("//?/S:/ca.pem", {}, {"S:": r"\??\C:\certs"}),
        # A local device path in forward slashes read as a share: was True.
        (r"C:\certs\ca.pem", {r"C:\certs\ca.pem": "//./C:/real/ca.pem"}, {}),
        ("//./C:/certs/ca.pem", {}, {}),
    ],
)
def test_review_a_forward_slash_device_prefix_is_not_cleared(
    path: str, links: dict[str, str], substs: dict[str, str]
) -> None:
    """``_strip_win_prefix`` reads backslash prefixes only, and normpath turns these into one
    after it has looked. The walk now names them a device path it does not read."""
    assert _walk(path, links, substs=substs, cwd=_no_cwd) is None


def test_review_a_volume_guid_path_is_still_walked() -> None:
    """The control: a volume GUID path keeps its prefix and is walked, in either separator."""
    assert _walk(r"\\?\Volume{0000}\certs\ca.pem", cwd=_no_cwd) is False
    assert _walk("//?/Volume{0000}/certs/ca.pem", cwd=_no_cwd) is False


def test_review_a_walk_cause_needs_a_kind() -> None:
    """No fallback from ``kind`` to the text, which can name a path. Red: the text was the kind."""
    with pytest.raises(TypeError):
        anchor_path.WalkCause(r"C:\phi-name is a mount point")  # type: ignore[call-arg]
    assert anchor_path.WalkCause.plain("fixed").kind == "fixed"


def test_review_a_working_directory_failure_is_named_as_one(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def gone() -> str:
        raise FileNotFoundError(2, "gone")

    caplog.set_level(logging.WARNING, logger=database.logger.name)
    assert _walk("ca.pem", cwd=gone) is None
    assert any("working directory" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("value", [True, False])
def test_review_the_lane_check_refuses_a_boolean_sslca(
    monkeypatch: pytest.MonkeyPatch, value: bool
) -> None:
    """The build refuses a boolean ``odbc_params`` value before reading its text, so the lane check
    does too, before it walks or stats ``True``. Red: it walked the relative path ``True``."""

    def never(_path: str) -> bool | None:
        raise AssertionError("a boolean must be refused before it is walked")

    monkeypatch.setattr(database, "_path_verdict", never)
    settings: dict[str, Any] = {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", "SSLCA": value},
    }
    with pytest.raises(ValueError, match="must not be a boolean"):
        ta.database_ca_anchor_spec("OB_DB_GEN", settings)


def test_review_a_walk_cause_survives_copy_and_pickle() -> None:
    """A ChainFinding's reason holds a WalkCause, and asdict deep-copies it. Red: str's own
    ``__getnewargs__`` left out the required kind, so each raised TypeError."""
    cause = anchor_path.WalkCause(r"text naming C:\x", "kind")
    for clone in (copy.copy(cause), copy.deepcopy(cause), pickle.loads(pickle.dumps(cause))):
        assert clone == cause and clone.kind == "kind"


def test_review_a_working_directory_with_a_device_prefix_is_still_walked() -> None:
    """A relative path joined to a ``\\\\?\\C:\\...`` working directory is read as ``C:\\...``,
    not refused as a forward-slash device spelling."""
    assert _walk("ca.pem", cwd=r"\\?\C:\work") is False


def test_review_a_drive_target_that_cannot_be_read_ends_the_anchor_walk() -> None:
    """The anchor walk's reader raises for a query it could not read, and the walk answers a cause
    rather than reading the letter as a real volume."""

    def unread(_drive: str) -> str | None:
        raise OSError("the drive S: could not be read")

    _chain, cause = windows_chain(r"S:\ca.pem", r"C:\work", _probe(), drive_target=unread)
    assert cause is not None and "could not be read" in cause.kind
    assert _walk(r"S:\ca.pem") is False  # the control: no subst, a real volume


def test_review_an_empty_sslca_is_left_to_the_build() -> None:
    """An empty value names no file, so the lane check answers no anchor rather than a refusal
    that lane_ca_setting would report against tls_ca_file."""
    settings: dict[str, Any] = {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", "SSLCA": ""},
    }
    assert ta.database_ca_anchor_spec("OB_DB_GEN", settings) is None


# === turn 2 of #5197 =============================================================================

_OUT = "OB_DB_GEN"
_IN = "IB_DB_GEN"
_GENERIC: dict[str, Any] = {
    "dialect": "generic",
    "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
    "server": "db.synthetic.test",
}


def _generic(**params: object) -> dict[str, Any]:
    return {**_GENERIC, "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", **params}}


# --- PR 2738 finding 1: a subst drive onto a bare drive ------------------------------------------


def test_finding_1_a_subst_drive_onto_a_bare_drive_is_walked(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``DefineDosDevice`` can stand a letter for a bare drive (``\\??\\C:``), so ``S:\\ca.pem`` is
    ``C:\\ca.pem``. Red: the walk judged the target ``C:`` alone as drive-relative, refused it and
    warned a cause that was not there."""
    caplog.set_level(logging.WARNING, logger=database.logger.name)
    assert _walk(r"S:\ca.pem", substs={"S:": "\\??\\C:"}) is False
    assert caplog.records == []
    links = {r"C:\ca.pem": _SHARE + r"\ca.pem"}
    assert _walk(r"S:\ca.pem", links, substs={"S:": "\\??\\C:"}) is True
    _chain, cause = windows_chain(
        r"S:\ca.pem",
        _no_cwd,
        _probe(),
        drive_target=lambda d: "\\??\\C:" if d.upper() == "S:" else None,
    )
    assert cause is None


def test_finding_1_a_drive_relative_subst_target_is_still_a_cause() -> None:
    """The control: a target with a drive and no separator before the rest stays a cause."""
    assert _walk(r"S:\ca.pem", substs={"S:": "\\??\\C:certs"}) is None


# --- PR 2738 findings 4, 5 and 9: one QueryDosDeviceW reader -------------------------------------


def test_finding_5_both_walks_read_a_subst_drive_through_one_reader() -> None:
    """Red: database kept its own ``QueryDosDeviceW`` reader, with its own error text."""
    assert vars(database)["query_drive_target"] is anchor_path.query_drive_target
    if sys.platform == "win32":
        assert anchor_path.windows_host_readers().drive_target is anchor_path.query_drive_target


def test_finding_4_a_drive_read_cause_keeps_its_code_and_says_it_once() -> None:
    """The reader's error names the Win32 code in ``strerror``. Red on Windows, with the real
    reader: database's error was one argument, so the cause read "could not be read: the drive S:
    could not be read (winerror 6)", and the path-free kind read only "OSError"."""

    def unread(_drive: str) -> str | None:
        if sys.platform == "win32":
            return anchor_path.query_drive_target("C:\\")  # error 6, as finding 9 measures
        raise OSError(None, "Win32 error 6 (The handle is invalid.)")

    _chain, cause = windows_chain(r"S:\ca.pem", _no_cwd, _probe(), drive_target=unread)
    assert cause is not None
    assert cause.count("could not be read") == 1
    assert re.search(r"Win32 error [0-9]+ ", cause.kind) and "S:" not in cause.kind


def test_finding_9_the_drive_reader_raises_for_a_failed_query() -> None:
    """On Windows the real reader raises for a failed query other than "no such device", and
    answers ``None`` for a real volume. ``C:\\`` is not a device name, and ``QueryDosDeviceW``
    answers it with error 6 (measured on Windows 11, 2026-11-05). Red: the reader did not exist
    outside ``windows_host_readers``, so nothing pinned its raise."""
    if sys.platform != "win32":
        with pytest.raises(OSError):
            anchor_path.query_drive_target("C:")
        return
    with pytest.raises(OSError, match=r"Win32 error [0-9]+ ") as refused:
        anchor_path.query_drive_target("C:\\")
    assert refused.value.strerror is not None and refused.value.strerror.startswith("Win32 error ")
    assert anchor_path.query_drive_target(os.environ.get("SYSTEMDRIVE", "C:")) is None


# --- PR 2738 finding 2: sslkey and sslpassword read by the text sent -----------------------------


def test_finding_2_an_sslkey_of_zero_counts_as_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """The build sends ``SSLKEY=0``, so the key comes from the file ``0``, which its own check
    reads, and ``sslcert`` is not read for a key. Red: truthiness read ``0`` as unset."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    read: list[str] = []

    def reading(path: str, _limit: int) -> bytes:
        read.append(path)
        return b"-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(database, "read_if_regular", reading)
    database._refuse_weak_driver_cert({"sslkey": 0, "sslcert": "client.pem"})
    assert read == []
    database._refuse_weak_driver_cert({"sslcert": "client.pem"})  # the control: no sslkey
    assert read == ["client.pem"]


def test_finding_2_an_sslpassword_of_zero_counts_as_given(monkeypatch: pytest.MonkeyPatch) -> None:
    """The build sends ``sslpassword=0``, a passphrase the driver unlocks with, so the wrap check
    is told one was given. Red: truthiness told it none was."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    monkeypatch.setattr(database, "read_if_regular", lambda _p, _n: b"synthetic key")
    given: list[bool] = []

    def recording(_data: bytes, **kwargs: Any) -> None:
        given.append(kwargs["passphrase_given"])

    monkeypatch.setattr(database, "refuse_weak_key_wrap", recording)
    database._refuse_weak_driver_key({"sslkey": "client.key", "sslpassword": 0})
    database._refuse_weak_driver_key({"sslkey": "client.key"})  # the control: none given
    assert given == [True, False]


# --- PR 2738 finding 6: one literal check for the build and the lane check ------------------------


@pytest.mark.parametrize("value", [True, "C:\\certs\\ca.pem ", "C:\\certs;\\ca.pem"])
def test_finding_6_the_lane_check_refuses_a_value_with_the_builds_own_text(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    """The lane check and the build refuse a boolean or a bad literal through one function, so the
    two refusals cannot drift apart. Red: the lane check copied the boolean check with its own
    wording."""
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    settings = _generic(SSLCA=value)
    with pytest.raises(ValueError) as built:
        database._build_odbc_dsn(settings, connection=_OUT)
    with pytest.raises(ValueError) as checked:
        ta.database_ca_anchor_spec(_OUT, settings)
    assert str(checked.value) == str(built.value)


# --- closing step 4, ask item 18: the lane check judges every driver file keyword ----------------


@pytest.mark.parametrize("keyword", ["SSLCAPATH", "SSLCERT", "SSLKEY"])
@pytest.mark.parametrize("verdict", [True, None])
def test_item_18_the_lane_check_refuses_a_driver_path_that_turned_remote(
    monkeypatch: pytest.MonkeyPatch, keyword: str, verdict: bool | None
) -> None:
    """A path the build cleared that later leads off the host, or that the walk can no longer
    clear, is refused at the lane check, as ``sslca`` is. The refusal names the keyword, never the
    path. Red: the lane check judged ``sslca`` only, so these got no refusal."""
    settings = _generic(**{keyword: r"C:\phi-name\client.pem"})
    assert ta.lane_anchor_spec("outbound", _OUT, settings) is None  # cleared at the build
    monkeypatch.setattr(database, "_path_verdict", lambda _p: verdict)
    for direction, name in (("outbound", _OUT), ("inbound", _IN)):
        with pytest.raises(ValueError, match=f"odbc_params {keyword.lower()} must be a") as refused:
            ta.lane_anchor_spec(direction, name, settings)
        assert "phi-name" not in str(refused.value)


@pytest.mark.parametrize("keyword", ["SSLCAPATH", "SSLCERT", "SSLKEY"])
def test_item_18_a_poller_naming_only_another_driver_path_is_lane_checked(keyword: str) -> None:
    """A ``DatabasePoll`` with no ``sslca`` still goes to the lane check when it names another
    driver file, and a refused one names that keyword. Red: the gate counted ``sslca`` only."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.pipeline import wiring_runner

    settings = _generic(**{keyword: r"C:\certs\client.pem"})
    assert ta.inbound_lane_reads_ca(ConnectorType.DATABASE, settings)
    assert wiring_runner._refused_setting_keys(settings) == f"odbc_params {keyword.lower()}"
    both = _generic(SSLCA=r"C:\certs\ca.pem", **{keyword: r"C:\certs\client.pem"})
    assert wiring_runner._refused_setting_keys(both) == f"odbc_params sslca or {keyword.lower()}"
    # The controls: no driver file, and a blank one, count for nothing.
    assert not ta.inbound_lane_reads_ca(ConnectorType.DATABASE, _generic())
    assert not ta.inbound_lane_reads_ca(ConnectorType.DATABASE, _generic(**{keyword: ""}))


async def test_item_18_the_real_lane_check_refuses_it_as_a_setting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from messagefoundry.store import MessageStore

    store = await MessageStore.open(tmp_path / "audit.db")
    try:
        check = ta.make_lane_anchor_check(store, enforcing=True)
        monkeypatch.setattr(database, "_path_verdict", lambda _p: True)
        with pytest.raises(ta.AnchorSettingRefused, match="odbc_params sslkey must be a"):
            await check("outbound", _OUT, _generic(SSLKEY=r"C:\certs\client.key"))
    finally:
        await store.close()


@pytest.mark.parametrize("value", [True, " client.key", ""])
def test_item_18_a_value_the_build_refuses_is_not_walked_by_the_lane_check(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    """A boolean or padded value is refused before any walk, and an empty one is left to the
    build's refusal, as for ``sslca``."""

    def never(_path: str) -> bool | None:
        raise AssertionError("a value the build refuses must not be walked")

    monkeypatch.setattr(database, "_path_verdict", never)
    settings = _generic(SSLKEY=value)
    if value == "":
        assert ta.lane_anchor_spec("outbound", _OUT, settings) is None
        return
    with pytest.raises(ValueError, match="sslkey"):
        ta.lane_anchor_spec("outbound", _OUT, settings)


# --- closing step 4: the entries of an SSLCAPATH folder ------------------------------------------


def _capath(tmp_path: Path, *names: str) -> Path:
    folder = tmp_path / "phi-capath"
    folder.mkdir()
    for name in names:
        (folder / name).write_bytes(b"synthetic")
    return folder


def _entry_verdicts(
    monkeypatch: pytest.MonkeyPatch, verdicts: Mapping[str, bool | None]
) -> list[str]:
    """Stand the probe and ``_path_verdict`` in: an entry named in ``verdicts`` is a link, which
    takes the full walk and gets its verdict there; any other entry is a plain file, and any other
    path walks ``False``. The walk beyond the spelling runs as on Windows. Returns the paths the
    full walk judged."""
    judged: list[str] = []

    def verdict(path: str) -> bool | None:
        judged.append(path)
        return verdicts.get(os.path.basename(path), False)

    def probe(path: str) -> tuple[str, str | None]:
        if os.path.basename(path) in verdicts:
            return LINK, r"C:\elsewhere"
        return FILE, None

    monkeypatch.setattr(database, "_WALKS_BEYOND_SPELLING", True)
    monkeypatch.setattr(database, "_path_verdict", verdict)
    monkeypatch.setattr(database, "_win_probe", probe)
    return judged


@pytest.mark.parametrize("verdict", [True, None])
def test_closing_step_4_an_sslcapath_entry_that_leaves_the_host_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verdict: bool | None
) -> None:
    """A driver opens ``<hash>.0`` in the folder by name, so a link there onto a share leads its CA
    lookup off the host. The build and the lane check refuse it, naming the keyword and never the
    path. Red: no entry was judged."""
    folder = _capath(tmp_path, "0a1b2c3d.0", "readme.txt")
    _entry_verdicts(monkeypatch, {"0a1b2c3d.0": verdict})
    settings = _generic(SSLCAPATH=str(folder))
    with pytest.raises(ValueError, match="'sslcapath' must name a folder whose entries") as built:
        database._build_odbc_dsn(settings, connection=_OUT)
    with pytest.raises(ValueError, match="sslcapath must name a folder whose entries") as checked:
        ta.lane_anchor_spec("outbound", _OUT, settings)
    for refused in (built, checked):
        assert "phi-capath" not in str(refused.value)


def test_closing_step_4_a_local_sslcapath_folder_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The control: none leaves the host, so the build and the lane check pass. A plain entry is
    judged by its probe alone, and a link takes the full walk, which clears it here."""
    folder = _capath(tmp_path, "0a1b2c3d.0", "0a1b2c3d.1")
    judged = _entry_verdicts(monkeypatch, {"0a1b2c3d.1": False})
    settings = _generic(SSLCAPATH=str(folder))
    database._build_odbc_dsn(settings, connection=_OUT)
    assert ta.lane_anchor_spec("outbound", _OUT, settings) is None
    walked = sorted(os.path.basename(p) for p in judged if p != str(folder))
    assert walked == ["0a1b2c3d.1", "0a1b2c3d.1"]  # once by the build, once by the lane check


@pytest.mark.parametrize("name", ["a.0:stream", "a.0 ", "a.0."])
def test_closing_step_4_an_entry_the_walk_ends_on_takes_the_full_walk(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """A name the walk ends on is never cleared by its probe alone. The probe would read it as a
    plain file; the full walk answers a cause. Synthetic names, so no folder is listed."""
    walked: list[str] = []
    monkeypatch.setattr(database, "_win_probe", lambda _p: (FILE, None))

    def verdict(path: str) -> bool | None:
        walked.append(path)
        return None

    monkeypatch.setattr(database, "_path_verdict", verdict)
    assert database._capath_entry_clear(rf"C:\capath\{name}", name) is False
    assert walked == [rf"C:\capath\{name}"]


def test_closing_step_4_an_entry_the_probe_cannot_read_takes_the_full_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(_path: str) -> tuple[str, str | None]:
        raise PermissionError(13, "denied")

    monkeypatch.setattr(database, "_win_probe", unreadable)
    monkeypatch.setattr(database, "_path_verdict", lambda _p: None)
    assert database._capath_entry_clear(r"C:\capath\a.0", "a.0") is False


def test_closing_step_4_a_folder_on_an_unreached_share_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Windows raises a share it could not reach (53, 67) as not found. Read as a missing folder,
    the value was cleared with no entry judged. Red: it was left to the driver."""
    folder = _capath(tmp_path, "a.0")
    _entry_verdicts(monkeypatch, {})
    real = os.scandir

    def unreached(path: str) -> Any:
        if os.fspath(path) == str(folder):
            exc = FileNotFoundError(2, "not reached")
            exc.winerror = 53  # type: ignore[attr-defined]
            raise exc
        return real(path)

    monkeypatch.setattr(os, "scandir", unreached)
    with pytest.raises(ValueError, match="'sslcapath' must name a folder whose entries"):
        database._build_odbc_dsn(_generic(SSLCAPATH=str(folder)), connection=_OUT)


def test_closing_step_4_the_refusal_fits_a_stored_failure() -> None:
    """A stored failure keeps about the first 200 characters, so the rule must end inside them for
    a connection name of ordinary length. Red: the entry rule ran past 200 and was cut."""
    prefix = "connection 'OB_ACME_LAB_DB'; DATABASE odbc_params value for 'sslcapath' "
    assert len(prefix + database.CAPATH_ENTRY_RULE) <= 200
    assert len(prefix + database.REMOTE_PATH_RULE) <= 200


def test_item_18_a_dialect_that_is_not_text_answers_no_value_on_the_lane_check() -> None:
    """A dialect that is not text answers no value, as before item 18, so the build refuses the
    dialect itself. Red: the lane check refused the keyword as None, before the build ran."""
    settings = {**_generic(SSLKEY=r"C:\certs\client.key"), "dialect": None}
    assert ta.lane_anchor_spec("outbound", _OUT, settings) is None


def test_closing_step_4_a_folder_past_the_entry_cap_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A folder the check would take too long to judge is refused rather than judged in part."""
    folder = _capath(tmp_path, "a.0", "b.0", "c.0")
    _entry_verdicts(monkeypatch, {})
    monkeypatch.setattr(database, "_MAX_CAPATH_ENTRIES", 2)
    with pytest.raises(ValueError, match="'sslcapath' must name a folder whose entries"):
        database._build_odbc_dsn(_generic(SSLCAPATH=str(folder)), connection=_OUT)


def test_closing_step_4_a_folder_that_cannot_be_listed_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    folder = _capath(tmp_path, "a.0")
    _entry_verdicts(monkeypatch, {})

    real = os.scandir

    def denied(path: str) -> Any:
        if os.fspath(path) == str(folder):
            raise PermissionError(13, "denied", str(folder))
        return real(path)

    monkeypatch.setattr(os, "scandir", denied)
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    with pytest.raises(ValueError, match="'sslcapath' must name a folder whose entries"):
        database._build_odbc_dsn(_generic(SSLCAPATH=str(folder)), connection=_OUT)
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warned and all("phi-capath" not in m for m in warned)


def test_closing_step_4_a_missing_folder_or_a_file_is_left_to_the_driver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _entry_verdicts(monkeypatch, {})
    database._build_odbc_dsn(_generic(SSLCAPATH=str(tmp_path / "absent")), connection=_OUT)
    single = tmp_path / "ca.pem"
    single.write_bytes(b"synthetic")
    database._build_odbc_dsn(_generic(SSLCAPATH=str(single)), connection=_OUT)


def test_closing_step_4_the_entries_are_not_listed_where_only_the_spelling_is_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """On POSIX the check reads nothing beyond the spelling (docs/CONNECTIONS.md), so the folder is
    not listed there."""
    folder = _capath(tmp_path, "a.0")

    real = os.scandir

    def never(path: str) -> Any:
        if os.fspath(path) == str(folder):
            raise AssertionError("the folder must not be listed")
        return real(path)

    monkeypatch.setattr(database, "_WALKS_BEYOND_SPELLING", False)
    monkeypatch.setattr(os, "scandir", never)
    monkeypatch.setattr(database, "_path_verdict", lambda _p: False)
    database._build_odbc_dsn(_generic(SSLCAPATH=str(folder)), connection=_OUT)
