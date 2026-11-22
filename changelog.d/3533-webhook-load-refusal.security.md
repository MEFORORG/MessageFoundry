- **Settings load now refuses an `[alerts].webhook_url` the alert notifier's build would refuse**
  on the checks that need no posture, so `messagefoundry check` and the `serve` pre-flight refuse it
  too. That covers at least a non-https scheme, a credential in the URL, a URL that does not parse
  or holds a space, control character or non-ASCII character inside it (outside a `#` fragment,
  which is not sent), a URL that names no host,
  a host off a non-empty `webhook_allowed_hosts`, and an over-length URL; the load check and the
  build call one function for those checks. A command that loads settings, such as
  `provision-admin`, now stops on such a URL; before, `provision-admin` dropped an http webhook
  with a WARNING and ran. These refusals do not repeat the URL, whose path can carry the webhook's
  token; the allowlist refusal names the host as urlsplit reads it, lower-cased. The WARNING the
  alert notifier logs for a failed webhook send now names the exception's class only, with no
  message and no traceback, since a send's exception text can quote the webhook URL; the other
  transports still log their exception and traceback. The static-credential
  report now lists `settings:alerts.webhook` as a static credential rather than as none (vault
  BACKLOG #3533 items 14 and 24).
