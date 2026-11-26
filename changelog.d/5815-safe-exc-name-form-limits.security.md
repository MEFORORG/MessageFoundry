- **`safe_exc` swaps a file name in more of the forms an error renders it in.** The part of the name
  after the last `/` is swapped too, so a POSIX or SFTP name holding a backslash no longer keeps its
  head; a cp1252 bytes path and an escape written with uppercase hex are swapped; and every form is
  swapped in one pass, so none matches across a label another wrote. A subdirectory a partner made
  under a recursive File source still stays in the message, as the docstring now says.
  (vault `BACKLOG #5815`)
