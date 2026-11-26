- **The engine AI broker's anchored opener is held by each app, not once for the process.** The
  opener `POST /ai/chat` dials where the `[tls]` anchor narrows was kept in one slot for the whole
  process, so two apps in one process with different `[tls]` policies would have evicted each
  other's opener on alternate requests and re-read the CA and CRL files each time, and the opener,
  with its `loaded_crls` record, outlived the app that built it. `create_app` now gives each app
  its own slot, the route holds the opener there, and the next assist call whose anchor narrows
  nothing empties it. A broker built directly, with no slot, holds no opener. Each refusal
  remedy is now written out in the source, so a grep for its opening words finds it.
  (`BACKLOG #5527`)
