- **`docs/PHI.md` now says what a second length cut does to an earlier truncation note, and states
  the custom-delimiter residual an operator could not read before.** No redaction output changes.
  The store cuts a diagnostic again after an emit site already bounded it. The doc said a stored
  value then ends in one count. That was wrong: an earlier note that ends before the new cut is
  most often kept, so a value can hold two counts. The doc also now says the count is per call,
  with earlier notes counted as plain characters. So it is not how much of the original text the
  value lacks, and a dropped `[redaction bound: ...]` marker takes its unscanned figure with it.
  Text a peer writes can end a stored value early, at least by quoting the opening of such a
  note. Section 7 said a feed declaring its own HL7 separators "is covered". It now names the
  accepted gap from `BACKLOG #1848`: when the 64 KiB scan bound drops the MSH that declares the
  delimiters, a custom-delimiter run in the kept text is not scrubbed. On a first deployment such
  a diagnostic would keep those field values in the log or the store. The details are in
  `docs/PHI.md`, under *The store's 200-character bound* and *A third residual*. New tests pin the
  note behaviour, and one pins that a token ending exactly on the limit is kept. (vault
  `BACKLOG #3034`, items 2 to 6)
