- **A log record holding a character a strict stream cannot encode no longer stops the engine.**
  Such a record rolled the stream sink, failed again on the same stream and recorded the sink
  unwritable, which asks for a stop. `serve` sets its stdout to replace such a character with `?`
  where the stream allows it, so the service's stdout did not hit this; a stream left strict did,
  at least one a caller of `configure_logging` did not harden or one whose reconfigure was refused.
  Now the line is written again with each character the stream has no byte for as a JSON
  `\uXXXX` escape, so a JSON sink's line still parses back to the record's text, and the fault is
  reported on the same rate-limited stderr line as a record that cannot be formatted. A sink that
  refuses the escaped line too still takes the two stages, and the line a roll re-writes is
  escaped for the stream the roll left. (`BACKLOG #5813`)
