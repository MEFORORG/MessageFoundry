- **`convert_case` title mode reads a UTF-8 hex escape as one character when deciding where a word
  starts, where `MSH-18` is empty or names UTF-8.** It read each byte of a hex escape as its own
  character, so the last byte of a UTF-8 letter could capitalize the next letter mid-word
  (`ren\XC3A9\e` became `Ren\XC3A9\E`) or keep the first letter of the next word lower case.
  The bytes of a run of adjacent hex escapes are now read as UTF-8 for that test; under any other
  declared character set each byte stays one character. Which `MSH-18` values count is stated in
  the docstring of `convert_case`. The escapes are still kept as sent in every mode, and a read of
  the value is unchanged. (`BACKLOG #5928`)
