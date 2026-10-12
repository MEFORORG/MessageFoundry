- **A redacted `UnicodeError` no longer prints a false position, and names a codec by a tighter
  rule.** Windows `mbcs` and `oem` errors raise with an empty span at index 0, wherever the
  character sat. `safe_exc` printed that as `position 0`. It now prints no position for an empty
  span, as in `'mbcs' codec cannot encode: invalid character`. A span of one or more characters
  reads as before. The codec name is printed only for a stdlib text codec or a non-numeric alias of
  one, or for `cp` plus one to five digits, the form Windows code pages report. So a real `oem`
  error now names `cp1`. A digit-only alias such as `1252`, the `aliases` helper module and the
  bytes-to-bytes transforms such as `base64` are no longer printed. (vault `BACKLOG #3206`,
  items 1, 2 and 4)
- **The Email destination refuses, at load, a subject whose encoded word decodes to a control
  character.** The header parser decodes RFC 2047 encoded words in the configured subject. So
  `=?utf-8?b?AA==?=` held no control character as text, and the message would have gone out with
  a raw NUL in its `Subject:` line. The destination now sets the subject on a scratch message at
  load and refuses a read-back that holds a control character. A site deploying such a subject
  would get a load refusal naming the setting, and never its value. An encoded word that decodes
  to plain text still loads. (vault `BACKLOG #3206`, item 6)
