- **A release stranded in `executing` now has a way out.**
  `GET /approvals/executing` lists every release still claimed as `executing`, with its claim owner
  and what an interrupt would judge of that owner. `POST /approvals/{id}/interrupt`, with
  `approvals:approve` and a fresh step-up, moves one to `interrupted` for the ordinary resolve. It is
  refused to the original requester, while this process runs the release, or while the owning
  cluster node still heartbeats, and an owner with no heartbeat to read needs the operator's
  recorded `attest_owner_stopped`, a JSON `true` only. A restart keeps the claim time in
  `decided_at` when it moves its own leftover release to `interrupted`, and reads other owners'
  rows apart from its own. See [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #1562`)
