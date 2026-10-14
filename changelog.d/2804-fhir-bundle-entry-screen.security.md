- **A FHIR `transaction` or `batch` connection now screens every Bundle entry before it posts.**
  It must declare `allowed_entry_methods`, which has no default, and may declare
  `allowed_entry_types`. An entry whose method, URL form or type the lists do not cover is refused,
  and so is a Bundle that is malformed, repeats a JSON key or names another `Bundle.type`. The
  message is dead-lettered and nothing is sent. A connection without the method list no longer
  loads. See [CONNECTIONS.md](../docs/CONNECTIONS.md), "A Bundle connection screens every entry".
  (`vault BACKLOG #2804`)
