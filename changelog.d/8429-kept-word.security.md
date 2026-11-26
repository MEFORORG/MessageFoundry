- **More words of a masked connection-string member value are masked before a `:` or `=`.** The
  member mask keeps a word whole there when it holds a word a later pass reads as a label, and it
  kept every word holding one anywhere, so a password word such as `Passage`, `Statement`,
  `Barcode`, `Compass`, `Codename` or `Bypass` would have printed whole on the write-time log
  filters, the support bundle and `GET /logs/tail`. Now a word holding a credential, token,
  key-label, query-filter or PHI JSON key word stays whole only where that word's reader opens on
  it, as `_read_as_label` in `messagefoundry/secretscrub.py` lists, so `ad_bind_password=`,
  `myPassword=`, `x.code=` and `session_state=` stay whole and `Passage:` or `x.name=` is masked.
  A word holding `MEFOR_`, the bundle marker, `basic`, `digest`, `mrn`, `0010` or a DICOM label
  word anywhere is still kept whole, so a password word such as `Outpatient` or `Basically` still
  prints there. A seeded differential of 60,006 lines over nine redaction paths, against the code
  before, printed no planted value the code before hid; it is a fuzz result, not a proof.
  (BACKLOG #8429, BACKLOG #5030)
