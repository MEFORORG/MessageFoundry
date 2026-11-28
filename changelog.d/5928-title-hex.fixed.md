- **`convert_case` title mode reads a UTF-8 hex escape as one character when deciding where a word
  starts.** It read each byte of a hex escape as its own character, so the last byte of a UTF-8
  letter could capitalize the next letter mid-word (`ren\XC3A9\e` became `Ren\XC3A9\E`) or keep the
  first letter of the next word lower case. Where the first repetition of `MSH-18`, stripped of
  surrounding space and in any case, is `UNICODE UTF-8` or `UTF-8`, the bytes of a run of adjacent
  hex escapes are now read as UTF-8 for that test. An empty or absent `MSH-18` declares ASCII, so
  there, as under any other declared character set, each byte stays one character. The escapes are
  still kept as sent, and a read of the value is unchanged. (`BACKLOG #5928`)
