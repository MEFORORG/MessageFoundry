- **More words of a masked connection-string member value are masked before a `:` or `=`.** The
  member mask kept whole every word holding one of its kept words, so a password word such as
  `Passage`, `Statement`, `Barcode`, `Compass`, `Codename` or `Bypass` would have printed whole on
  the write-time log filters, the support bundle and `GET /logs/tail`. Now such a word is kept
  only where `_read_as_label` in `messagefoundry/secretscrub.py` keeps it, mostly where the word
  ends in a label word at an opening that function lists, so `ad_bind_password=`, `myPassword=`,
  `x.code=` and `session_state=` stay whole and `Passage:` or `x.name=` is masked. Measured
  against the code before, over nine redaction paths and four seeded corpora (150,024 lines,
  HL7-prefixed and carriage-marker lines among them): 0 lines and 0 occurrences of a planted value
  printed that the code before hid. It is a fuzz result, not a proof. At least the words that
  function's docstring lists still print whole, as before, such as `Outpatient`,
  `Hunterbearer :`, `Name:`, `bar-code:`, `__token:`, the `Compass` of `{Zq7;Compass=Vw9}`, the
  `Vw9.Bypass` of `{Zq7;Vw9.Bypass=Kp2}`, and a password piece glued before a kept label, such as
  `Zq7.code=`. (BACKLOG #8429, BACKLOG #5030)
