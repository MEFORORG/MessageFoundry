- **At least some `auth.channel_denied` rows that name no channel now say which operation they
  refused.** A channel-scoped caller refused a config reload, its dry run, a reset of every
  statistic or a replay of every channel's dead letters gets a row whose detail carries
  `"operation"`, the name of the audit action the operation writes when it runs. Before, such
  rows from one actor could not be told apart. Some rows naming no channel still carry no
  operation, at least one for a malformed name a core handler such as `dual_role_control`
  refuses. No request is allowed or refused differently. (vault BACKLOG #3748 item 7)
