- **A `TM` value in `OBX-5` with a time-zone offset is no longer kept.** The `TM` grammar took an
  offset after the time, so a date written `YYYY-MMDD`, such as `1945-0612`, read as 19:45 at
  -06:12, and a phone number written `212555-0100` read as a time and an offset. Both would have
  left whole. An offset can also name a small region, which is why the `date` and `dob` kinds
  never keep one (vault `BACKLOG #2767`). A `TM` value with an offset now becomes `[REDACTED]`;
  a time of day without one is kept as before. The vendored `tee/anon/surrogates.py` copy changes
  the same way. (vault `BACKLOG #3493`)
