# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The FILE output name is bounded, and a name the message makes unwritable is permanent (ADR 0204).

Vault BACKLOG #2562. ``render_filename`` put a message field into the output name with no length
bound, and the default template is ``{MSH-10}.hl7``. A 400-character control id rendered a
404-character name, the write raised ``OSError``, and ``FileDestination`` wrapped it as a plain
``DeliveryError``, which the delivery worker retries as transient. One message would then hold a FIFO
lane for the whole retry budget. The P8 tests below reproduce that and fail on the unfixed code.

Deliberately ASCII-only source: pytest echoes a failing body to a cp1252 console on Windows, so
non-ASCII characters are written as escapes.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.file import FILENAME_MAX_BYTES, FileDestination, render_filename
from tests.test_remotefile_transport import _dest as _remote_dest
from tests.test_remotefile_transport import _FakeClient


def _adt(control_id: str) -> str:
    return f"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|{control_id}|P|2.5\rPID|1||1\r"


def _file_dest(directory: Path, **settings: Any) -> FileDestination:
    return FileDestination(
        Destination(
            name="OB_FILE",
            type=ConnectorType.FILE,
            settings={"directory": str(directory), **settings},
        )
    )


def _utf8(name: str) -> int:
    return len(name.encode("utf-8"))


# --- P8: the long control id -------------------------------------------------------------------


def test_p8_controls_render_as_before() -> None:
    """The probe's three control rows: an ordinary id, a traversal string, and a device name."""
    assert render_filename("{MSH-10}.hl7", _adt("CTRL1"), fallback="message") == "CTRL1.hl7"
    traversal = render_filename("{MSH-10}.hl7", _adt("..\\..\\x"), fallback="message")
    assert "/" not in traversal and "\\" not in traversal
    assert render_filename("{MSH-10}.hl7", _adt("NUL"), fallback="message") == "message"


def test_p8_a_400_character_control_id_falls_back_instead_of_a_404_character_name() -> None:
    name = render_filename("{MSH-10}.hl7", _adt("A" * 400), fallback="message")
    assert name == "message"
    assert _utf8(name) <= FILENAME_MAX_BYTES


async def test_p8_a_400_character_control_id_is_delivered_under_the_fallback_name(
    tmp_path: Path,
) -> None:
    """The unfixed code raised a transient DeliveryError here, which held the lane for 100 tries."""
    dest = _file_dest(tmp_path)
    await dest.send(_adt("A" * 400))
    assert [p.name for p in tmp_path.iterdir()] == ["message.hl7"]


# --- Rule 2: the cap is in encoded bytes and covers the suffix ------------------------------------


def test_the_cap_counts_utf8_bytes_not_characters() -> None:
    """100 two-byte characters plus ``.hl7`` is 104 characters but 204 bytes, over the cap."""
    name = render_filename("{MSH-10}.hl7", _adt("\u00e9" * 100), fallback="fb.hl7")
    assert name == "fb.hl7"


def test_a_name_exactly_at_the_cap_is_kept_and_one_byte_over_falls_back() -> None:
    at_cap = "A" * (FILENAME_MAX_BYTES - len(".hl7"))
    assert render_filename("{MSH-10}.hl7", _adt(at_cap), fallback="fb.hl7") == f"{at_cap}.hl7"
    over = at_cap + "A"
    assert render_filename("{MSH-10}.hl7", _adt(over), fallback="fb.hl7") == "fb.hl7"


def test_the_suffix_is_counted_and_is_added_to_the_fallback() -> None:
    """195 + ``.hl7`` is 199 bytes and fits; with ``.gz`` it is 202 and does not."""
    body = _adt("A" * 195)
    assert _utf8(render_filename("{MSH-10}.hl7", body, fallback="fb.hl7")) == 199
    assert render_filename("{MSH-10}.hl7", body, fallback="fb.hl7", suffix=".gz") == "fb.hl7.gz"
    assert render_filename("{MSH-10}.hl7", _adt("C1"), fallback="fb", suffix=".gz") == "C1.hl7.gz"


async def test_a_gzip_destination_caps_the_name_with_its_gz_suffix(tmp_path: Path) -> None:
    dest = _file_dest(tmp_path, compress="gzip")
    await dest.send(_adt("A" * 195))
    assert [p.name for p in tmp_path.iterdir()] == ["message.hl7.gz"]


def test_a_lone_surrogate_never_reaches_the_name() -> None:
    name = render_filename("{MSH-10}.hl7", _adt("ab\ud800cd"), fallback="fb.hl7")
    assert name == "ab_cd.hl7"


# --- Rule 3: trailing dots and spaces, and the fuller reserved list -------------------------------


@pytest.mark.parametrize(
    "control_id",
    ["NUL ", "nul.", "NUL. .", "CONIN$", "conout$", "COM\u00b9", "LPT\u00b3", "AUX  "],
)
def test_a_device_name_hidden_by_trailing_dots_or_spaces_falls_back(control_id: str) -> None:
    assert render_filename("{MSH-10}.hl7", _adt(control_id), fallback="fb.hl7") == "fb.hl7"


def test_a_space_before_the_extension_does_not_hide_a_device_name() -> None:
    assert render_filename("{MSH-10} .hl7", _adt("NUL"), fallback="fb.hl7") == "fb.hl7"


def test_trailing_dots_and_spaces_are_stripped_from_the_final_name() -> None:
    assert render_filename("{MSH-10}", _adt("abc. ."), fallback="fb") == "abc"
    assert render_filename("{MSH-10}", _adt(". ."), fallback="fb") == "fb"


def test_an_ordinary_name_beginning_with_a_device_word_is_kept() -> None:
    assert render_filename("{MSH-10}.hl7", _adt("NULLIFY"), fallback="fb") == "NULLIFY.hl7"


# --- Rule 1: a name the destination judges unwritable is permanent --------------------------------


async def test_a_name_that_escapes_the_directory_is_a_permanent_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _file_dest(tmp_path / "out")
    monkeypatch.setattr(file_mod, "render_filename", lambda *a, **k: "../escape.hl7")
    with pytest.raises(NegativeAckError) as caught:
        await dest.send(_adt("C1"))
    assert caught.value.permanent is True
    # The rendered name is not in the error: it reaches the store's last_error.
    assert "escape" not in str(caught.value)
    assert not (tmp_path / "escape.hl7").exists()


async def test_a_resolve_outside_the_directory_for_another_reason_stays_transient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A link at the name, or a share that changes form between the two resolves, is the
    environment and not the message, so it is retried rather than dead-lettered."""
    dest = _file_dest(tmp_path)
    real_resolve = Path.resolve

    def _resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "C1.hl7":
            return real_resolve(tmp_path.parent / "elsewhere" / self.name)
        return real_resolve(self, strict)

    monkeypatch.setattr(Path, "resolve", _resolve)
    with pytest.raises(DeliveryError, match="outside the destination directory") as caught:
        await dest.send(_adt("C1"))
    assert not isinstance(caught.value, NegativeAckError)
    assert "C1" not in str(caught.value)


# --- Rule 5: an OSError from the filesystem stays transient ---------------------------------------


async def test_an_os_error_from_the_write_stays_transient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _file_dest(tmp_path)

    def _full_disk(*_a: Any, **_k: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tempfile, "mkstemp", _full_disk)
    with pytest.raises(DeliveryError) as caught:
        await dest.send(_adt("C1"))
    assert not isinstance(caught.value, NegativeAckError)


# --- Rule 4: the directory depth, judged at configuration time ------------------------------------


def _limit_leaving(monkeypatch: pytest.MonkeyPatch, directory: Path, room: int) -> None:
    """Make the platform path limit leave exactly ``room`` bytes for a name in ``directory``."""
    used = file_mod._path_units(os.path.abspath(directory)) + 1 + file_mod._DERIVED_NAME_HEADROOM
    monkeypatch.setattr(file_mod, "_path_limit", lambda _absolute: used + room)


def test_a_directory_too_deep_for_the_fallback_name_is_refused_at_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limit_leaving(monkeypatch, tmp_path, len("message.hl7") - 1)
    with pytest.raises(ValueError, match="too deep"):
        _file_dest(tmp_path)


def test_a_gzip_destination_needs_room_for_the_fallback_and_its_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limit_leaving(monkeypatch, tmp_path, len("message.hl7"))
    _file_dest(tmp_path)  # the plain fallback fits exactly
    with pytest.raises(ValueError, match="too deep"):
        _file_dest(tmp_path, compress="gzip")


async def test_a_deep_directory_shrinks_the_cap_so_a_long_name_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limit_leaving(monkeypatch, tmp_path, 50)
    dest = _file_dest(tmp_path)
    await dest.send(_adt("B" * 46))  # 50 bytes with .hl7: fits exactly
    await dest.send(_adt("A" * 47))  # 51 bytes: falls back
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"{'B' * 46}.hl7", "message.hl7"]


def test_a_shallow_directory_keeps_the_full_cap() -> None:
    assert file_mod._name_budget(Path("/d"), "") == FILENAME_MAX_BYTES


def test_a_reduced_cap_is_logged_once_at_build_and_names_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _limit_leaving(monkeypatch, tmp_path, 50)
    with caplog.at_level(logging.WARNING, logger=file_mod.__name__):
        _file_dest(tmp_path, overwrite=True)
    messages = [r.getMessage() for r in caplog.records if "leaves 50 bytes" in r.getMessage()]
    assert len(messages) == 1
    assert "each fallback replaces the last" in messages[0]


def test_a_template_whose_fixed_text_is_over_the_cap_is_refused_at_build(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="fixed text"):
        _file_dest(tmp_path, filename="X" * FILENAME_MAX_BYTES + "_{MSH-10}.hl7")


def test_the_long_path_prefix_lifts_the_windows_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(file_mod, "_windows_long_paths_enabled", lambda: False)
    assert file_mod._path_limit("C:\\out") == file_mod._WIN_MAX_PATH
    assert file_mod._path_limit("\\\\?\\C:\\out") == file_mod._WIN_LONG_PATH


# --- The remote file destination shares the default cap -------------------------------------------


async def test_p8_a_remote_upload_falls_back_instead_of_a_404_character_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    dest = _remote_dest(monkeypatch, client)
    await dest.send(_adt("A" * 400))
    assert list(client.files) == ["/in/message.hl7"]
    # The temp name it stored first is derived from the capped name, so it is bounded too.
    stored = [path for op, path in client.ops if op == "store"]
    assert all(_utf8(path.rsplit("/", 1)[1]) <= 255 for path in stored)


def test_a_remote_template_whose_fixed_text_is_over_the_cap_is_refused_at_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="fixed text"):
        _remote_dest(monkeypatch, _FakeClient(), filename="X" * FILENAME_MAX_BYTES + "{MSH-10}.hl7")


def test_the_template_check_counts_a_suffix_the_template_already_carries_once() -> None:
    """``render_filename`` does not add ``.gz`` to a name that ends with it, so neither may the check:
    196 bytes plus ``.gz`` is 199 and fits, where adding it twice would read 202."""
    file_mod._check_template_fits("X" * 196 + "{MSH-10}.gz", ".gz", FILENAME_MAX_BYTES)
    with pytest.raises(ValueError, match="fixed text"):
        file_mod._check_template_fits("X" * 198 + "{MSH-10}.gz", ".gz", FILENAME_MAX_BYTES)
