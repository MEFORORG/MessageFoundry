- **The audit export checks the caller again before each page.** `GET /audit/export` and the
  console's `/ui/audit/export` resolve the session before every page of up to 1,000 rows. A
  revoked session, a withdrawn `audit:export`, a pending password change or an unmet second factor
  records `audit.export.stopped` with counts only and aborts the download. So does a caller that
  has lost `users:manage` since the export started, because the pages would still carry the lock
  rows. On a first deployment, a revoked grant would otherwise have kept receiving the rest of an
  export of up to 1,000,000 rows. (`BACKLOG #1154`)
