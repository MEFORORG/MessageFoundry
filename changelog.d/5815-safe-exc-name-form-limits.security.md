- **`safe_exc` swaps a file name in more of the forms an error renders it in.** The part of the name
  after the last `/` is swapped too, so a POSIX or SFTP name holding a backslash no longer keeps its
  head; a bytes path in the locale's encoding or cp1252, and an escape written with uppercase hex,
  are swapped; and no form can match across a label another form wrote. A subdirectory a partner
  made under a recursive File source still stays in the message, as the docstring and
  `docs/PHI.md` now say. (vault `BACKLOG #5815`)
