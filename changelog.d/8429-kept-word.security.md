- **More words of a masked connection-string member value are masked before a `:` or `=`.** The
  member mask keeps a word whole there when it holds a word a later pass reads as a label, and it
  kept every word holding one anywhere, so a password word such as `Passage`, `Statement`,
  `Barcode`, `Compass`, `Codename` or `Bypass` would have printed whole on the write-time log
  filters, the support bundle and `GET /logs/tail`. Now an ASCII word holding a credential, token,
  key-label, query-filter or PHI JSON key word is kept by this rule at the openings
  `_read_as_label` in `messagefoundry/secretscrub.py` lists, so `ad_bind_password=`,
  `myPassword=`, `x.code=` and `session_state=` stay whole and `Passage:` or `x.name=` is masked.
  At least these would still print whole on first deployment, as before: a word holding
  `MEFOR_`, the bundle marker, `basic`, `digest`, `mrn`, `0010` or a DICOM label word anywhere,
  such as `Outpatient`, `Basically`, `Digestive`, `Kv20010x` or `Kvmrn`; a word holding part of a
  carriage-marker head with no colon after its `v1` (`mfb64:v1Passage:`); a word ending in
  `bearer`, `basic`, `digest` or `mrn` before white space, even before a `:` or `=`, such as
  `Hunterbearer :`; a whole label word, such as `Name:`; a query key at a word boundary or a
  `%XX` escape whatever follows it, such as `bar-code:`, `x.state:` or `%2Fstate=`; a
  credential, token or key-label word after any `_`, such as `__token:` (a query key or PHI JSON
  key word there, such as `x_code=` or `x_name=`, is masked); a word after a `;` inside a braced
  value that ends in a member key word before `=`, such as the `Compass` of `{Zq7;Compass=Vw9}`,
  which a later handler can read as a member key, so masking it printed a value the code before
  hid; and a word holding a character outside ASCII. A seeded
  differential against the code before, over nine redaction paths including the bundle reading
  a chain line back, printed no planted value the code before hid, by lines or by occurrences, on
  four corpora: two of 60,006 lines dense with kept-word shapes, 24,006 HL7-prefixed lines, and
  6,006 lines with a kept word after a carriage head. It is a fuzz result over those shapes, not
  a proof. (BACKLOG #8429, BACKLOG #5030)
