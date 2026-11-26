- **Two Windows path checks read a device-prefixed spelling as Windows opens it.** The start
  check's link walk stripped a `\\.\` or forward-slash prefix from a link target and walked the
  rest as a local path, which Win32 may open as another object; it now refuses any link target the
  trust-anchor walk refuses as a device path. The key-file check collapsed `.` and `..` with
  `os.path.abspath` before its walk saw the text, so `\\?\C:\x\..\k` was judged as `C:\k`, which the
  open never reads, and `\\.\C:\..\UNC\h\s\k` as the local `C:\UNC\h\s`; such a spelling is now
  refused before that step. (`BACKLOG #5515`)
