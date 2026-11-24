- **An `auth.channel_denied` row that names no channel by design now says which operation it
  refused.** A channel-scoped caller refused a config reload or a reset of every statistic gets a
  row whose detail carries `"operation"`, `config_reload` or `stats_reset`, the audit action the
  operation writes when it runs. The web console's bulk routes and purge confirm page tag theirs
  the same way. Before, two such rows from one actor could not be told apart. No request is
  allowed or refused differently. (vault BACKLOG #3748 item 7)
