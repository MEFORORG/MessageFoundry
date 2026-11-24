- **At least some `auth.channel_denied` rows that name no channel now say which operation they
  refused.** A channel-scoped caller refused a config reload, its dry run, a reset of every
  statistic or a replay of every channel's dead letters gets a row whose detail carries
  `"operation"`, the name of the audit action the operation writes when it runs. Before, such
  rows from one actor could not be told apart. A core handler such as `_dual_role_control` in
  `messagefoundry/api/app.py` passes no operation, so it would write a row with no channel and no
  operation only if called directly with a malformed name; no shipped route does. No request is allowed or refused differently. (vault BACKLOG #3748 item 7)
