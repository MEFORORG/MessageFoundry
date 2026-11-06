- **A release stranded in `executing` now has a way out, and a restart reads the audit trail first.**
  `GET /approvals/executing` lists every release still claimed as `executing`, with its claim owner
  and what an interrupt would judge of that owner. `POST /approvals/{id}/interrupt`, with
  `approvals:approve` and a fresh step-up, moves one to `interrupted` for the ordinary resolve. It is
  refused while this process runs the release or while the owning cluster node still heartbeats, and
  an owner with no heartbeat to read needs the operator's recorded `attest_owner_stopped`. A restart
  now settles its own leftover release to `approved` or `failed` when the trail holds that outcome
  row, with an `approval.reconciled` row, keeps the claim time in `decided_at`, and reads other
  owners' rows apart from its own. See [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #1562`)
