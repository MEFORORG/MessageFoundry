- **A non-https `[alerts].webhook_url` is now refused when settings load**, so `messagefoundry check`
  and the `serve` pre-flight refuse it too, not only the alert notifier's build. A URL that does not
  parse, or that holds a control character or surrounding spaces, is refused the same way. The
  message repeats nothing of the URL, whose path can carry the webhook's token. The static-credential
  report now lists `settings:alerts.webhook` as a static credential rather than as none (vault
  BACKLOG #3533 items 14 and 24).
