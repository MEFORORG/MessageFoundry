- **The engine declares a `[webconsole]` extra again.** `pip install "messagefoundry[webconsole]"`
  installs the engine with the web console wheel, `messagefoundry-webconsole>=0.5.3`, with no
  ceiling. The console's own floor on the engine makes the pair a cycle, which uv and pip both
  resolve. Engine 0.5.3 on PyPI does not carry the extra; the first engine release built from this
  change does.
