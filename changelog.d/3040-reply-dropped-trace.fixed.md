- **A delivery whose 2xx reply body was dropped over the size bound now says so on the message.**
  REST with capture off, and a plain FHIR write with capture off, record a `reply_dropped` event
  on the message, with the status and the bound and no byte of the reply. The WARNING now names
  the message, and is logged only after the row is recorded as delivered, so it no longer reports
  a record that might not exist. (vault `BACKLOG #3040`)
