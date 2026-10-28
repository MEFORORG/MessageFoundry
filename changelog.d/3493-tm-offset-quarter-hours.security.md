- **A `TM` value in `OBX-5` is kept only with an offset in whole quarter hours.** The `TM` grammar
  took any offset minutes up to 59, so a date written `YYYY-MMDD`, such as `1945-0612`, read as
  19:45 at an offset of -06:12 and would have left whole. Every UTC offset in use is a whole
  quarter hour, so an offset's minutes must now be `00`, `15`, `30` or `45`, and a value with any
  other offset becomes `[REDACTED]`. Such a date on the 15th or the 30th still fits, and
  [PHI.md](../docs/PHI.md) section 9 names it. The vendored `tee/anon/surrogates.py` copy changes
  the same way. (vault `BACKLOG #3493`)
