- **The store's `replay`, `replay_dead`, `resend_to` and `reingress` now require `audit=`.** It is
  keyword-only with no default on the Store protocol and on the SQLite, PostgreSQL and SQL Server
  stores, as `cancel_queued` already was, so a direct caller can no longer run one and record no
  operator row by leaving the argument out. The 0.5.2 entry's contrast, that the store methods take
  `audit=` while the Engine methods require it, no longer holds: both require it now.
  At least three store methods keep an optional `audit`: `enqueue_ingress`, because it is also the
  partner receipt path, and the approval gate's `create_pending_approval` and
  `decide_pending_approval`. (`BACKLOG #2624`)
