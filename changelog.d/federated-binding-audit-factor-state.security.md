- **The federated bind, rebind and unbind audit rows say whether the account holds engine
  factors.** `auth.federated_subject_bound`, `auth.federated_subject_rebound` and
  `auth.federated_subject_unbound` now carry `totp_enrolled` and `webauthn_enrolled`. A bind or
  rebind row reads them when the old binding is removed, so it can miss a factor change made just
  before the new binding is written.
  ([Keep a local Administrator](../docs/SECURITY.md#keep-a-local-administrator), vault BACKLOG #2711)
