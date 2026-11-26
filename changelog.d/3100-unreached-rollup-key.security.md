- **One rollup of unreachable accounts cannot silence a later one.** The notifier keys its
  re-alert cooldown and an operator's suspend by type and source. Under one shared rollup source,
  inside the cooldown of the last rollup sent, or while any rollup was suspended, a later rollup
  would page nobody: at least one account entering after five or more were paged, and a later
  rollup of other accounts. Each rollup pages under
  `directory-reconciler-unreached-rollup:<key>`, keyed by the accounts entering, so it is its
  own instance, and an INFO line logs the key. A cooldown or suspend reaches only a later
  rollup of the same accounts; a set that differs, even one of accounts paged before, pages.
  To match every unreachable-account
  alert, an `[alerts]` rule names `directory-reconciler-unreached*` (vault BACKLOG #3100 item 14).
