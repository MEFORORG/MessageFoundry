- **`serve`'s dual-control advisory also fires for a narrowed held list.** On an exposed instance
  it warned only while `[approvals].enabled` was off. With dual control on and an
  `[approvals].operations` list that leaves out a default operation, or holds none, the left-out
  actions still complete on one caller's authority, and it said nothing. It now warns there too,
  naming what was left out, in the words `security show` and `GET /security/posture` use. It still
  only warns. (vault `BACKLOG #3474`)
