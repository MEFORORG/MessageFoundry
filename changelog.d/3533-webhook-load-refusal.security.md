- **A non-https `[alerts].webhook_url` is now refused when settings load**, so `messagefoundry check`
  and the `serve` pre-flight refuse it too, not only the alert notifier's build. A URL that does not
  parse, or that holds a control character inside it, is refused the same way. A command that
  loads settings, such as `provision-admin`, now stops on such a URL; before, `provision-admin`
  dropped the webhook with a WARNING and ran. The message repeats nothing of the URL, whose path can carry the webhook's token. The static-credential
  report now lists `settings:alerts.webhook` as a static credential rather than as none (vault
  BACKLOG #3533 items 14 and 24).
