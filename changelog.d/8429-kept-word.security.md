- **A word of a masked connection-string member value that only holds a label word is masked
  too.** The member mask keeps a word whole before a `:` or `=` where a later pass reads it as a
  label, and it kept every word holding one of those label words anywhere, so a password word such
  as `Passage`, `Statement`, `Barcode`, `Compass`, `Codename` or `Bypass` would have printed whole
  on the write-time log filters, the support bundle and `GET /logs/tail`. Now such a word stays
  whole only where the label word's own reader opens on it, as `_read_as_label` in
  `messagefoundry/secretscrub.py` lists, so `ad_bind_password=`, `myPassword=`, `x.code=` and
  `session_state=` stay whole and `Passage:` or `x.name=` is masked. A seeded differential of
  60,006 lines over nine redaction paths, against the code before, printed no planted value the
  code before hid; it is a fuzz result, not a proof. (BACKLOG #8429, BACKLOG #5030)
