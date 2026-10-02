- **The captured-reply and outbound-payload bodies now need `messages:view_summary` as well as
  `messages:view_raw`.** `GET /messages/{id}/outbound` answers 403 and writes an
  `auth.permission_denied` row for a caller missing either. `GET /messages/{id}/responses` returns a
  null `body` to one. Owner ruling R18 makes these one-message requests the reveal act only for a
  `view_summary` holder, and an ADR 0045 custom role could hold `view_raw` alone. No built-in role
  changes: Administrator and Operator hold both. See
  [SECURITY.md](../docs/SECURITY.md). (ASVS 14.2.6, vault `BACKLOG #1187`)
