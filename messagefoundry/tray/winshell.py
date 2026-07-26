"""The Windows notification-area shell for the tray (ADR 0113 §2/§4/§8/§9).

A hand-rolled ``ctypes`` message pump: a hidden window receives the ``Shell_NotifyIcon`` callback,
renders the context menu with ``TrackPopupMenuEx``, re-adds the icon on Explorer restart
(``TaskbarCreated``), flips the icon on a taskbar-theme change (``WM_SETTINGCHANGE`` /
``ImmersiveColorSet``), and cleans up on logoff. The GUI lives on the main thread; the poller thread
pushes updates via :meth:`TrayShell.request_update` (a thread-safe ``PostMessageW`` → the pump reads
the pending slot and repaints). All decidable logic (state machine, menu, id↔action) lives in the
pure modules — this file is the thin, manual-QA'd Win32 glue (a pywin32 rewrite is the ADR 0113
escape hatch if it misbehaves).

Windows-only. Importing it elsewhere is fine (constants + structs load); :meth:`TrayShell.run`
raises off Windows.
"""

from __future__ import annotations

import ctypes
import logging
import sys
import threading
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from messagefoundry.tray.menu import Action, MenuItem, assign_command_ids

log = logging.getLogger("messagefoundry.tray.winshell")

# --- Win32 constants --------------------------------------------------------
_WM_APP = 0x8000
WM_TRAYICON = _WM_APP + 1
_WM_TRAY_UPDATE = _WM_APP + 2
_WM_TRAY_NOTIFY = _WM_APP + 3
_WM_TRAY_QUIT = _WM_APP + 4

_WM_NULL = 0x0000
_WM_DESTROY = 0x0002
_WM_CLOSE = 0x0010
_WM_QUERYENDSESSION = 0x0011
_WM_ENDSESSION = 0x0016
_WM_SETTINGCHANGE = 0x001A
_WM_CONTEXTMENU = 0x007B
_WM_LBUTTONDBLCLK = 0x0203
_NIN_SELECT = 0x0400
_NIN_KEYSELECT = 0x0401

_NIM_ADD, _NIM_MODIFY, _NIM_DELETE, _NIM_SETVERSION = 0, 1, 2, 4
_NIF_MESSAGE, _NIF_ICON, _NIF_TIP, _NIF_INFO, _NIF_SHOWTIP = 0x01, 0x02, 0x04, 0x10, 0x80
_NOTIFYICON_VERSION_4 = 4
_NIIF_INFO = 0x01
_NIIF_RESPECT_QUIET_TIME = 0x80

_IMAGE_ICON = 1
_LR_LOADFROMFILE, _LR_DEFAULTSIZE = 0x10, 0x40

_MF_STRING, _MF_SEPARATOR, _MF_GRAYED, _MF_CHECKED = 0x0000, 0x0800, 0x0001, 0x0008
_TPM_RIGHTBUTTON, _TPM_RETURNCMD, _TPM_NONOTIFY = 0x0002, 0x0100, 0x0080

_WS_OVERLAPPED = 0x00000000
_CW_USEDEFAULT = -0x80000000
_TRAY_UID = 1
_CLASS_NAME = "MessageFoundryTrayWnd"

if sys.platform == "win32":
    WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t
    )
else:  # a cross-platform stand-in so the module imports/type-checks off Windows (run() still raises)
    WNDPROC = ctypes.CFUNCTYPE(
        ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t
    )


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", _GUID),
        ("hBalloonIcon", wintypes.HICON),
    )


class _WNDCLASSEXW(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    )


class TrayShell:
    """Owns the hidden window, the notification icon, and the message loop (main thread only)."""

    def __init__(
        self,
        *,
        on_menu: Callable[[], list[MenuItem]],
        on_action: Callable[[Action], None],
        on_double_click: Callable[[], None],
        on_theme_change: Callable[[], None] = lambda: None,
        on_session_end: Callable[[], None] = lambda: None,
    ) -> None:
        self._on_menu = on_menu
        self._on_action = on_action
        self._on_double_click = on_double_click
        self._on_theme_change = on_theme_change
        self._on_session_end = on_session_end

        self._hwnd: int | None = None
        self._lock = threading.Lock()
        self._pending_icon: str | None = None
        self._pending_tip: str = "MessageFoundry"
        self._pending_toast: tuple[str, str] | None = None
        self._icon_cache: dict[str, int] = {}
        self._taskbar_created_msg = 0
        self._added = False

        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._wndproc = WNDPROC(self._wnd_proc)  # keep a strong ref (GC would break the pump)
        self._configure_prototypes()

    def _configure_prototypes(self) -> None:
        """Declare argtypes/restypes so 64-bit pointer/WPARAM/LPARAM values are not truncated to 32
        bits (the default), which would overflow on ``DefWindowProcW``/``PostMessageW`` etc."""
        u, s, k = self._user32, self._shell32, self._kernel32
        hwnd, uint, size_t, ssize_t = (
            wintypes.HWND,
            wintypes.UINT,
            ctypes.c_size_t,
            ctypes.c_ssize_t,
        )
        u.DefWindowProcW.restype = ssize_t
        u.DefWindowProcW.argtypes = (hwnd, uint, size_t, ssize_t)
        u.PostMessageW.restype = wintypes.BOOL
        u.PostMessageW.argtypes = (hwnd, uint, size_t, ssize_t)
        u.CreateWindowExW.restype = hwnd
        u.CreateWindowExW.argtypes = (
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            hwnd,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            ctypes.c_void_p,
        )
        u.RegisterWindowMessageW.restype = uint
        u.GetMessageW.restype = ctypes.c_int
        u.LoadImageW.argtypes = (
            wintypes.HINSTANCE,
            wintypes.LPCWSTR,
            uint,
            ctypes.c_int,
            ctypes.c_int,
            uint,
        )
        u.CreatePopupMenu.restype = wintypes.HMENU
        u.AppendMenuW.argtypes = (wintypes.HMENU, uint, size_t, wintypes.LPCWSTR)
        u.TrackPopupMenuEx.restype = ctypes.c_int  # TPM_RETURNCMD → the chosen command id
        u.TrackPopupMenuEx.argtypes = (
            wintypes.HMENU,
            uint,
            ctypes.c_int,
            ctypes.c_int,
            hwnd,
            ctypes.c_void_p,
        )
        u.SetMenuDefaultItem.argtypes = (wintypes.HMENU, uint, wintypes.BOOL)
        u.DestroyMenu.argtypes = (wintypes.HMENU,)
        u.SetForegroundWindow.argtypes = (hwnd,)
        u.GetCursorPos.argtypes = (ctypes.c_void_p,)
        u.DestroyWindow.argtypes = (hwnd,)
        u.DestroyIcon.argtypes = (wintypes.HICON,)
        u.LoadImageW.restype = wintypes.HANDLE
        s.Shell_NotifyIconW.restype = wintypes.BOOL
        s.Shell_NotifyIconW.argtypes = (wintypes.DWORD, ctypes.c_void_p)
        k.GetModuleHandleW.restype = wintypes.HMODULE

    # --- public API (thread-safe where noted) ---

    def run(self, icon_path: Path, tooltip: str) -> None:
        """Create the window, add the icon, and pump messages until quit. Main thread only."""
        if sys.platform != "win32":
            raise RuntimeError("TrayShell.run is Windows-only")
        self._pending_icon = str(icon_path)
        self._pending_tip = tooltip
        self._create_window()
        self._add_icon()
        self._message_loop()

    def request_update(self, icon_path: Path, tooltip: str) -> None:
        """Thread-safe: queue an icon/tooltip change and wake the pump to apply it."""
        with self._lock:
            self._pending_icon = str(icon_path)
            self._pending_tip = tooltip
        self._post(_WM_TRAY_UPDATE)

    def request_notify(self, title: str, body: str) -> None:
        """Thread-safe: queue a balloon toast."""
        with self._lock:
            self._pending_toast = (title, body)
        self._post(_WM_TRAY_NOTIFY)

    def request_quit(self) -> None:
        """Thread-safe: ask the pump to tear down and exit."""
        self._post(_WM_TRAY_QUIT)

    # --- window / icon plumbing ---

    def _post(self, msg: int) -> None:
        if self._hwnd:
            self._user32.PostMessageW(wintypes.HWND(self._hwnd), msg, 0, 0)

    def _create_window(self) -> None:
        hinst = self._kernel32.GetModuleHandleW(None)
        self._taskbar_created_msg = self._user32.RegisterWindowMessageW("TaskbarCreated")
        wc = _WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = _CLASS_NAME
        if not self._user32.RegisterClassExW(ctypes.byref(wc)):
            # Class may already exist from a prior run in-process; ignore that specific case.
            log.debug("RegisterClassExW returned 0 (err=%s)", ctypes.get_last_error())
        self._user32.CreateWindowExW.restype = wintypes.HWND
        hwnd = self._user32.CreateWindowExW(
            0,
            _CLASS_NAME,
            "MessageFoundry Tray",
            _WS_OVERLAPPED,
            _CW_USEDEFAULT,
            _CW_USEDEFAULT,
            _CW_USEDEFAULT,
            _CW_USEDEFAULT,
            None,
            None,
            hinst,
            None,
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self._hwnd = hwnd

    def _load_icon(self, path: str) -> int:
        cached = self._icon_cache.get(path)
        if cached:
            return cached
        self._user32.LoadImageW.restype = wintypes.HANDLE
        handle = self._user32.LoadImageW(
            None, path, _IMAGE_ICON, 0, 0, _LR_LOADFROMFILE | _LR_DEFAULTSIZE
        )
        if handle:
            self._icon_cache[path] = handle
        return handle or 0

    def _base_nid(self) -> _NOTIFYICONDATAW:
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = wintypes.HWND(self._hwnd)
        nid.uID = _TRAY_UID
        return nid

    def _add_icon(self) -> None:
        with self._lock:
            icon_path, tip = self._pending_icon, self._pending_tip
        nid = self._base_nid()
        nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP | _NIF_SHOWTIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._load_icon(icon_path) if icon_path else 0
        nid.szTip = tip[:127]
        self._shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid))
        # NOTIFYICON_VERSION_4 must be (re)set after every NIM_ADD.
        ver = self._base_nid()
        ver.uVersion = _NOTIFYICON_VERSION_4
        self._shell32.Shell_NotifyIconW(_NIM_SETVERSION, ctypes.byref(ver))
        self._added = True

    def _apply_update(self) -> None:
        with self._lock:
            icon_path, tip = self._pending_icon, self._pending_tip
        if not self._added:
            return
        nid = self._base_nid()
        nid.uFlags = _NIF_ICON | _NIF_TIP | _NIF_SHOWTIP
        nid.hIcon = self._load_icon(icon_path) if icon_path else 0
        nid.szTip = tip[:127]
        self._shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(nid))

    def _apply_notify(self) -> None:
        with self._lock:
            toast = self._pending_toast
            self._pending_toast = None
        if toast is None or not self._added:
            return
        title, body = toast
        nid = self._base_nid()
        nid.uFlags = _NIF_INFO
        nid.szInfoTitle = title[:63]
        nid.szInfo = body[:255]
        nid.dwInfoFlags = _NIIF_INFO | _NIIF_RESPECT_QUIET_TIME
        self._shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(nid))

    def _remove_icon(self) -> None:
        if self._added and self._hwnd:
            nid = self._base_nid()
            self._shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))
            self._added = False
        for handle in self._icon_cache.values():
            self._user32.DestroyIcon(handle)
        self._icon_cache.clear()

    # --- menu ---

    def _show_menu(self) -> None:
        items = self._on_menu()
        rendered, mapping = assign_command_ids(items)
        hmenu = self._user32.CreatePopupMenu()
        default_id = 0
        for item, cmd_id in rendered:
            if item.separator:
                self._user32.AppendMenuW(hmenu, _MF_SEPARATOR, 0, None)
                continue
            flags = _MF_STRING
            if item.action is None or not item.enabled:
                flags |= _MF_GRAYED
            if item.checked:
                flags |= _MF_CHECKED
            self._user32.AppendMenuW(hmenu, flags, cmd_id, item.label)
            if item.default and cmd_id:
                default_id = cmd_id
        if default_id:
            self._user32.SetMenuDefaultItem(hmenu, default_id, False)

        point = wintypes.POINT()
        self._user32.GetCursorPos(ctypes.byref(point))
        self._user32.SetForegroundWindow(wintypes.HWND(self._hwnd))
        chosen = self._user32.TrackPopupMenuEx(
            hmenu,
            _TPM_RIGHTBUTTON | _TPM_RETURNCMD | _TPM_NONOTIFY,
            point.x,
            point.y,
            wintypes.HWND(self._hwnd),
            None,
        )
        self._user32.PostMessageW(wintypes.HWND(self._hwnd), _WM_NULL, 0, 0)  # dismissal fix
        self._user32.DestroyMenu(hmenu)
        action = mapping.get(int(chosen))
        if action is not None:
            self._dispatch(action)

    def _dispatch(self, action: Action) -> None:
        try:
            self._on_action(action)
        except Exception:  # an action must never crash the pump (supervisory boundary)
            log.exception("tray action %s raised", action)

    # --- window procedure ---

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == WM_TRAYICON:
            event = lparam & 0xFFFF
            if event in (_WM_CONTEXTMENU, _NIN_SELECT, _NIN_KEYSELECT):
                self._show_menu()
            elif event == _WM_LBUTTONDBLCLK:
                self._dispatch_double_click()
            return 0
        if msg == _WM_TRAY_UPDATE:
            self._apply_update()
            return 0
        if msg == _WM_TRAY_NOTIFY:
            self._apply_notify()
            return 0
        if msg == _WM_TRAY_QUIT:
            self._user32.DestroyWindow(wintypes.HWND(hwnd))
            return 0
        if msg == _WM_SETTINGCHANGE:
            if lparam and _lparam_str(lparam) == "ImmersiveColorSet":
                self._safe(self._on_theme_change, "theme-change")
            return 0
        if self._taskbar_created_msg and msg == self._taskbar_created_msg:
            self._added = False
            self._add_icon()
            return 0
        if msg == _WM_QUERYENDSESSION:
            return 1  # allow logoff/shutdown
        if msg == _WM_ENDSESSION:
            self._safe(self._on_session_end, "session-end")
            self._remove_icon()
            return 0
        if msg == _WM_DESTROY:
            self._remove_icon()
            self._user32.PostQuitMessage(0)
            return 0
        return int(self._user32.DefWindowProcW(wintypes.HWND(hwnd), msg, wparam, lparam))

    def _dispatch_double_click(self) -> None:
        self._safe(self._on_double_click, "double-click")

    def _safe(self, fn: Callable[[], None], label: str) -> None:
        try:
            fn()
        except Exception:  # callbacks must never crash the pump
            log.exception("tray %s callback raised", label)

    def _message_loop(self) -> None:
        msg = wintypes.MSG()
        get = self._user32.GetMessageW
        get.restype = ctypes.c_int
        while True:
            ret = get(ctypes.byref(msg), None, 0, 0)
            if ret in (0, -1):
                break
            self._user32.TranslateMessage(ctypes.byref(msg))
            self._user32.DispatchMessageW(ctypes.byref(msg))
        self._remove_icon()


def _lparam_str(lparam: int) -> str:
    """Best-effort read of a wide string an LPARAM points to (WM_SETTINGCHANGE area name)."""
    try:
        return ctypes.wstring_at(lparam)
    except (OSError, ValueError):
        return ""
