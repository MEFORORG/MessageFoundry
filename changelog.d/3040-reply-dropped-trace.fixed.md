- **A delivery whose 2xx reply body was dropped over the size bound now says so on the message.**
  REST with capture off, and a plain FHIR write with capture off, record a `reply_dropped` event
  on the message in the same write that marks it delivered, with the status and the bound and no
  byte of the reply. The WARNING now names the message, comes after that write, and says whether
  the write recorded anything. (vault `BACKLOG #3040`)
