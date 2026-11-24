- **At least some `auth.channel_denied` rows that name no channel now say which operation they
  refused.** A channel-scoped caller refused a config reload, its dry run, a reset of every
  statistic or a replay of every channel's dead letters gets a row whose detail carries
  `"operation"`, the audit action the operation writes when it runs. The web console's bulk routes
  and purge confirm page tag theirs the same way, and a bulk selection whose name fails the
  connection-name rule is now also marked `"malformed_name": true`. Before, such rows from one actor
  could not be told apart. Some rows naming no channel still carry no operation, at least one from
  a per-name connection route. No request is allowed or refused differently. (vault BACKLOG #3748
  item 7)
