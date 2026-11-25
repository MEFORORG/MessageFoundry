- **A log record holding a character the sink's stream cannot encode no longer stops the engine.**
  On a stdout with a narrow encoding, such as cp1252 under NSSM on a stock Windows host, such a
  record rolled the stream sink, failed again on the same stream and recorded the sink unwritable,
  which asks for a stop. Now the line is written again with each character the stream has no byte
  for as a JSON `\uXXXX` escape, so a JSON sink's line still parses back to the record's text, and
  the fault is reported on the same rate-limited stderr line as a record that cannot be formatted.
  A sink that refuses the escaped line too still takes the two stages, and after a roll the
  escaped line is the one re-written. (`BACKLOG #5813`)
