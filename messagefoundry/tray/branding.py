"""Branded launcher so Windows names the tray "MessageFoundry Tray", not "Python" (ADR 0113).

Windows 11's "Other system tray icons" list (Settings → Personalization → Taskbar) names an icon
after its owning **process executable's** version info (``FileDescription``) — not the icon tooltip
(verified against the live ``HKCU\\Control Panel\\NotifyIconSettings`` entries, which key on
``ExecutablePath``). Launched as ``pythonw -m messagefoundry.tray`` the process image is Python's own
``pythonw.exe``, so the list says "Python".

The fix: keep a branded ``MessageFoundryTray.exe`` in the venv ``Scripts\\`` dir and re-exec the tray
through it. It must be a copy of the **base** interpreter's ``pythonw.exe``, NOT the venv's — the
venv ``pythonw.exe`` is a redirector STUB that spawns the base interpreter as a child, so that child
(image ``pythonw.exe``) would own the icon and the branding would be lost. A copy of the *base*
``pythonw.exe`` in ``Scripts\\`` runs **in-process** instead: it finds ``pyvenv.cfg`` one dir up (so
the venv is active and ``tray`` imports) and its own top-level runtime DLLs — which we stage beside
it (``python3XX.dll`` et al., ~7 MB, since a standalone interpreter's runtime is app-local, not in
System32) — so the process image is ``MessageFoundryTray.exe``. Only its ``RT_VERSION`` resource is
rewritten (a fresh ``VS_VERSIONINFO`` built here in pure stdlib) so ``FileDescription`` reads
"MessageFoundry Tray". Autostart still pins the plain ``pythonw`` and lets this re-exec apply branding
at runtime, so it never depends on the derived exe surviving between logins.

Everything is fail-soft: any failure returns ``None``/``False`` and the tray simply runs unbranded
(listed as "Python"). The builder (:func:`build_version_info`) is pure and unit-tested; the acid
test is Windows' own parser reading the description back from a real copy (:func:`read_file_description`),
verified on a live box (in-process, venv active, image = the branded exe).
"""

from __future__ import annotations

import ctypes
import logging
import re
import shutil
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from messagefoundry.tray import __version__

log = logging.getLogger("messagefoundry.tray.branding")

_LEADING_DIGITS = re.compile(r"\d+")

BRANDED_EXE_NAME = "MessageFoundryTray.exe"
FILE_DESCRIPTION = "MessageFoundry Tray"
_PRODUCT_NAME = "MessageFoundry"
_LANG_EN_US_UNICODE = "040904b0"  # StringTable key: lang 0x0409 (en-US), charset 0x04B0 (Unicode)
_RT_VERSION = 16
_RES_ID_VERSION = 1
_LANG_NEUTRAL_SET = 1033  # what we write (en-US)


# --- VS_VERSIONINFO builder (pure; struct layout per verrsrc.h) -------------------------------


def _pad_to_dword(offset: int) -> bytes:
    """Zero padding so the next field lands on a 32-bit boundary (offsets are block-relative)."""
    return b"\x00" * ((4 - offset % 4) % 4)


def _node(key: str, wtype: int, value: bytes, value_length: int, children: bytes = b"") -> bytes:
    """One VS_VERSIONINFO pseudo-node: wLength, wValueLength, wType, szKey, [pad] value [pad] kids."""
    key_bytes = (key + "\x00").encode("utf-16-le")
    body = struct.pack("<HH", value_length, wtype) + key_bytes
    body += _pad_to_dword(2 + len(body))  # +2 for the wLength WORD that prefixes the body
    body += value
    if children:
        body += _pad_to_dword(2 + len(body))
        body += children
    return struct.pack("<H", 2 + len(body)) + body


def _string_node(name: str, value: str) -> bytes:
    text = (value + "\x00").encode("utf-16-le")
    return _node(name, 1, text, len(value) + 1)  # wValueLength counts WCHARs incl. the null


def _sibling_join(nodes: list[bytes]) -> bytes:
    out = b""
    for node in nodes:
        out += _pad_to_dword(len(out)) + node
    return out


def _fixed_file_info(version: tuple[int, int, int, int]) -> bytes:
    """``VS_FIXEDFILEINFO`` (52 bytes): signature, struct version, file/product versions, VFT_APP."""
    ms = (version[0] << 16) | version[1]
    ls = (version[2] << 16) | version[3]
    return struct.pack(
        "<13I",
        0xFEEF04BD,  # dwSignature
        0x00010000,  # dwStrucVersion
        ms,
        ls,  # dwFileVersion
        ms,
        ls,  # dwProductVersion
        0x3F,  # dwFileFlagsMask
        0,  # dwFileFlags
        0x00040004,  # dwFileOS = VOS_NT_WINDOWS32
        0x00000001,  # dwFileType = VFT_APP
        0,  # dwFileSubtype
        0,
        0,  # dwFileDate
    )


def _version_tuple() -> tuple[int, int, int, int]:
    # VS_FIXEDFILEINFO is four 16-bit fields: take each segment's LEADING digit run (so "0rc1" → 0,
    # not 01) and clamp to 0xFFFF (so a large calendar-ish version can never overflow struct.pack).
    parts: list[int] = []
    for piece in __version__.split("."):
        match = _LEADING_DIGITS.match(piece)
        parts.append(min(int(match.group()), 0xFFFF) if match else 0)
    while len(parts) < 4:
        parts.append(0)
    return (parts[0], parts[1], parts[2], parts[3])


def build_version_info() -> bytes:
    """A complete, fresh ``VS_VERSIONINFO`` block naming the tray. Pure — testable anywhere."""
    version = _version_tuple()
    dotted = ".".join(str(p) for p in version[:3])
    strings = _sibling_join(
        [
            _string_node("CompanyName", _PRODUCT_NAME),
            _string_node("FileDescription", FILE_DESCRIPTION),
            _string_node("FileVersion", dotted),
            _string_node("InternalName", "MessageFoundryTray"),
            _string_node("OriginalFilename", BRANDED_EXE_NAME),
            _string_node("ProductName", _PRODUCT_NAME),
            _string_node("ProductVersion", dotted),
        ]
    )
    string_table = _node(_LANG_EN_US_UNICODE, 1, b"", 0, strings)
    string_file_info = _node("StringFileInfo", 1, b"", 0, string_table)
    translation = struct.pack("<HH", 0x0409, 0x04B0)
    var_node = _node("Translation", 0, translation, len(translation))
    var_file_info = _node("VarFileInfo", 1, b"", 0, var_node)
    fixed = _fixed_file_info(version)
    return _node(
        "VS_VERSION_INFO", 0, fixed, len(fixed), _sibling_join([string_file_info, var_file_info])
    )


# --- Windows resource plumbing (win32-only; fail-soft) ----------------------------------------


def read_file_description(exe: Path) -> str | None:
    """What Windows' own version parser reads back — the same source the tray-icon list uses."""
    if sys.platform != "win32":
        return None
    version_dll = ctypes.WinDLL("version", use_last_error=True)
    version_dll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version_dll.GetFileVersionInfoSizeW.argtypes = (wintypes.LPCWSTR, ctypes.c_void_p)
    version_dll.GetFileVersionInfoW.restype = wintypes.BOOL
    version_dll.GetFileVersionInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    version_dll.VerQueryValueW.restype = wintypes.BOOL
    version_dll.VerQueryValueW.argtypes = (
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    size = version_dll.GetFileVersionInfoSizeW(str(exe), None)
    if not size:
        return None
    buffer = ctypes.create_string_buffer(size)
    if not version_dll.GetFileVersionInfoW(str(exe), 0, size, buffer):
        return None
    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    query = rf"\StringFileInfo\{_LANG_EN_US_UNICODE}\FileDescription"
    if not version_dll.VerQueryValueW(buffer, query, ctypes.byref(pointer), ctypes.byref(length)):
        return None
    if not pointer.value or not length.value:
        return None
    return ctypes.wstring_at(pointer.value, length.value).rstrip("\x00")


def _existing_version_langs(exe: Path) -> list[int]:
    """Language ids of the exe's current RT_VERSION resource (so stale ones can be deleted)."""
    if sys.platform != "win32":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.restype = wintypes.HMODULE
    kernel32.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
    kernel32.FreeLibrary.argtypes = (wintypes.HMODULE,)
    load_as_data = 0x00000002 | 0x00000020  # DATAFILE | IMAGE_RESOURCE
    module = kernel32.LoadLibraryExW(str(exe), None, load_as_data)
    if not module:
        return []
    langs: list[int] = []
    enum_proc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HMODULE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.WORD,
        ctypes.c_ssize_t,
    )

    def _collect(_h: int, _type: int, _name: int, lang: int, _param: int) -> int:
        langs.append(int(lang))
        return 1

    callback = enum_proc(_collect)
    kernel32.EnumResourceLanguagesW.argtypes = (
        wintypes.HMODULE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        enum_proc,
        ctypes.c_ssize_t,
    )
    kernel32.EnumResourceLanguagesW(module, _RT_VERSION, _RES_ID_VERSION, callback, 0)
    kernel32.FreeLibrary(module)
    return langs


def _set_version_resource(exe: Path, data: bytes) -> bool:
    """Replace the exe's RT_VERSION with ``data`` (deleting any other-language copies)."""
    if sys.platform != "win32":
        return False
    stale_langs = [lang for lang in _existing_version_langs(exe) if lang != _LANG_NEUTRAL_SET]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE
    kernel32.BeginUpdateResourceW.argtypes = (wintypes.LPCWSTR, wintypes.BOOL)
    kernel32.UpdateResourceW.restype = wintypes.BOOL
    kernel32.UpdateResourceW.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.WORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.EndUpdateResourceW.restype = wintypes.BOOL
    kernel32.EndUpdateResourceW.argtypes = (wintypes.HANDLE, wintypes.BOOL)

    handle = kernel32.BeginUpdateResourceW(str(exe), False)
    if not handle:
        return False
    for lang in stale_langs:
        # Deleting a stale-language copy is best-effort; the 1033 write below is what matters.
        kernel32.UpdateResourceW(handle, _RT_VERSION, _RES_ID_VERSION, lang, None, 0)
    ok = bool(
        kernel32.UpdateResourceW(
            handle, _RT_VERSION, _RES_ID_VERSION, _LANG_NEUTRAL_SET, data, len(data)
        )
    )
    if not bool(kernel32.EndUpdateResourceW(handle, False)):
        ok = False
    return ok


# --- public API --------------------------------------------------------------------------------


def is_branded_process() -> bool:
    """True when the current process image already is the branded launcher."""
    return Path(sys.executable).name.lower() == BRANDED_EXE_NAME.lower()


def _base_pythonw() -> Path:
    """The **base** interpreter's ``pythonw.exe`` — a real in-process interpreter, not the venv
    redirector stub. A copy of THIS in the venv ``Scripts\\`` runs in-process and keeps the venv."""
    base = getattr(sys, "_base_executable", None)
    if base:
        candidate = Path(base).with_name("pythonw.exe")
        if candidate.is_file():
            return candidate
    return Path(sys.base_exec_prefix) / "pythonw.exe"


def _stage_runtime(base_dir: Path, scripts: Path) -> None:
    """Copy the base interpreter's top-level runtime DLLs beside the branded exe so it loads without
    the venv redirector (a standalone interpreter's ``python3XX.dll``/vcruntime are app-local). Only
    missing/older DLLs are copied; an in-use DLL (same version) is left as-is (per-file fail-soft)."""
    for dll in base_dir.glob("*.dll"):
        target = scripts / dll.name
        try:
            if not target.exists() or target.stat().st_mtime < dll.stat().st_mtime:
                shutil.copy2(dll, target)
        except OSError:
            log.warning("could not stage runtime dll %s (kept existing)", dll.name)


def ensure_branded_launcher(scripts_dir: Path | None = None) -> Path | None:
    """Create/refresh ``MessageFoundryTray.exe`` in the venv ``Scripts\\``. ``None`` on any failure.

    Copies the BASE ``pythonw.exe`` (not the venv redirector) + its runtime DLLs, then rewrites the
    copy's version resource. Idempotent: an up-to-date branded copy is returned untouched (DLLs are
    re-ensured cheaply either way). Fail-soft by design — an AV block, a read-only dir, or a
    resource-API failure just means the tray runs unbranded.
    """
    if sys.platform != "win32":
        return None
    scripts = scripts_dir or Path(sys.executable).parent
    source = _base_pythonw()
    destination = scripts / BRANDED_EXE_NAME
    if not source.is_file():
        # Expected when the interpreter moved/was rebuilt — a quiet fallback, not an error.
        log.info("base interpreter %s not found; the tray will run unbranded", source)
        return None
    try:
        fresh = (
            destination.is_file()
            and destination.stat().st_mtime >= source.stat().st_mtime
            and read_file_description(destination) == FILE_DESCRIPTION
        )
        _stage_runtime(source.parent, scripts)  # ensure the DLLs are present regardless
        if fresh:
            return destination
        shutil.copy2(source, destination)
        if not _set_version_resource(destination, build_version_info()):
            log.warning("could not rewrite the version resource of %s", destination)
            return None
        if read_file_description(destination) != FILE_DESCRIPTION:
            log.warning("branded launcher wrote, but Windows reads no FileDescription back")
            return None
        log.info("branded launcher ready: %s", destination)
        return destination
    except Exception:  # branding is cosmetic — ANY failure must degrade to running unbranded
        log.exception("could not create the branded launcher in %s", scripts)
        return None


_CHILD_STARTUP_GRACE_S = 0.6


def relaunch_branded() -> bool:
    """Spawn the tray under the branded launcher. True = the branded child took over (exit); False =
    branding unavailable or the child died at once, so the caller must run unbranded itself."""
    branded = ensure_branded_launcher()
    if branded is None:
        return False
    try:
        child = subprocess.Popen([str(branded), "-m", "messagefoundry.tray"], close_fds=True)  # nosec B603 - fixed argv (our own branded launcher + module name), shell=False
    except OSError:
        log.exception("could not relaunch via %s", branded)
        return False
    # A bad copy / AV kill can make the child die immediately. Don't leave the user with NO tray:
    # if it exits within the grace window, fall back to running unbranded in this process.
    try:
        child.wait(timeout=_CHILD_STARTUP_GRACE_S)
    except subprocess.TimeoutExpired:
        return True  # still alive → it owns the tray
    log.warning("branded child exited immediately (code %s); running unbranded", child.returncode)
    return False
