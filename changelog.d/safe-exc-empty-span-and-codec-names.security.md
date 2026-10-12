- **A redacted `UnicodeError` no longer prints a false position, and names a codec by a tighter
  rule.** Windows `mbcs` and `oem` errors raise with an empty span at index 0, wherever the
  character sat. `safe_exc` printed that as `position 0`. It now prints no position for an empty
  span, as in `'mbcs' codec cannot encode: invalid character`. A span of one or more characters
  reads as before. The codec name is printed only for a stdlib text codec or a non-numeric alias of
  one, or for `cp` plus one to five digits, the form Windows code pages report. So a real `oem`
  error now names `cp1`. A digit-only alias such as `1252`, the `aliases` helper module and the
  bytes-to-bytes transforms such as `base64` are no longer printed. (vault `BACKLOG #3206`,
  items 1, 2 and 4)
