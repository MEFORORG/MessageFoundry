- **A log line holding a character the stream cannot encode no longer stops a healthy sink.** On
  a strict stream, such as a cp1252 stdout, the log write guard rolled the sink, failed the
  re-write the same way and recorded the sink unwritable, which could ask for the stop. The line
  is now written again with each such character as a JSON `\uXXXX` escape, and the escape is
  counted on the rate-limited stderr format-fault line. A sink that refuses the escaped line too is
  handled as any failed write. (`BACKLOG #5813`)
