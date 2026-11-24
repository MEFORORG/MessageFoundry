- **`GET /connections/{name}/events` resolves the name through the same rule as `/metadata`,
  `/test`, `/start`, `/stop` and `/restart`.** With the engine started, a channel-scoped caller now
  gets the 403 and an `auth.channel_denied` row for an inbound another engine shard holds, a
  scope-listed outbound, and a scope-listed name that exists nowhere, where it was answered from
  the store. With no runner only the channel scope is checked, as before. `GET /events?connection=`
  is unchanged. (`BACKLOG #3031`)
