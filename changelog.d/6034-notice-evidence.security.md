- **A role-change or account-disable security notice now says only what its sender confirmed.**
  It says the roles were changed only when the role write is known to have committed, and that
  the sessions already open on the account were ended only when the session revoke returned.
  Otherwise it says that this could not be confirmed, and an unconfirmed role change closes with
  "If you did not expect this notice". This holds for an administrator's change and a directory
  one alike: before, a directory role notice could say the roles changed and the sessions ended
  after a role write or a revoke that raised. An administrator's role-change notice now names the
  roles set, each by its id, and the federated link and unlink notices name the identity
  provider. A directory reconcile that ended sessions but wrote no role now sends
  the "sessions were ended" notice instead of a role-change notice. The client address on a
  notice is printed only as one printable token, and a directory notice no longer says the
  address belonged to a sign-in. (`BACKLOG #6034`)
