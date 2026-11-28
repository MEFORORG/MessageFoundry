- **A log line holding a character the stream cannot encode no longer stops a healthy sink, nor
  turns into `?` on serve's stdout.** On a strict stream, such as a cp1252 stdout, the log write
  guard rolled the sink, failed the re-write the same way and recorded the sink unwritable, which
  could ask for the stop. On serve's default stdout, which serve sets to replace such a
  character, the line was written with `?`. The guard now writes each such character as a JSON
  `\uXXXX` escape, taken before the write for the stream's encoding, so the escape wins on both.
  The escape is counted on the rate-limited stderr format-fault line only: it raises no alert and
  shows nothing on `GET /status`. A sink that refuses the escaped line too is handled as any
  failed write, and still reaches the stop. (`BACKLOG #5813`)
