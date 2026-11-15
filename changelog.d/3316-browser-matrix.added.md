- **The web console's supported browser versions are published, derived from the features it
  uses.** [BROWSER-SUPPORT.md](../docs/BROWSER-SUPPORT.md#supported-browser-versions) gains a
  table with one row per browser feature the console relies on, giving the desktop Chrome, Edge,
  Firefox and Safari version from which each supports it and the dataset entry each number was
  read from (MDN browser-compat-data 8.1.9, and caniuse-db for CSP nonce sources). Each browser's
  floor is the latest version in its column, with the features it leaves out named: Chrome 89,
  Edge 89, Firefox 138 and Safari 17. Nothing enforces these versions, and no browser is refused
  for being older. The page's `Clear-Site-Data` row no longer says Safari lacks it: the dataset
  records Safari support for the `"cache"` value from 17, and marks every Chrome and Edge version
  it records for that value partial. A test holds the table to the features the code uses and
  recomputes each floor from the rows. (`BACKLOG #3316`, `#1124`)
