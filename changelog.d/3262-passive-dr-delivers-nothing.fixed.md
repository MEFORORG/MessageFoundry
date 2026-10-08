- **A passive DR box delivers nothing.** With `[dr].enabled = true` and the box not activated, at
  start or after `POST /dr/release`, every outbound is parked: it reads `status: "filtered"` and
  holds its rows. It used to build every outbound. A box started over a store restored from a
  backup then delivered the rows that backup held undelivered, possibly while the primary was
  alive and delivering the same rows. `POST /dr/activate` delivers on the outbounds at or above
  `[dr].priority_threshold`, each held row once and in order. A release now parks every outbound
  when its drain ends, so rows left on the released box stay queued there. The reload after a
  release no longer starts a parked outbound. An operator start, stop or restart of an outbound
  on a passive box answers `409`. The router and transform stages still run on a passive box.
  (`vault BACKLOG #3262`)
