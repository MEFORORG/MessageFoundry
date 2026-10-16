- **A refused federated step-up records where it started.** An `auth.reauth` row for a step-up
  refused after its flow was redeemed now carries `start_client` and `client_moved`, as the row of
  a completed step-up does. Both come from the flow the start leg staged, never from the token. A
  refusal before the `state` check carries neither. The refusal a step-up gate sends an `oidc`
  session now says to repeat the action in the web console, because a bare `/ui/reauth` names no
  action and returns to `/ui`. A store fault while that refusal reads the session's sign-in
  mechanism now keeps the `403`, with the password wording, rather than answering `500`. See
  [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3145`)
