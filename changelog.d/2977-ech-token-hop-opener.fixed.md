- **An OAuth2 or SMART token hop behind an ECH sidecar posts through a plain opener.** (`BACKLOG
  #2977`) The engine sends the token request to the loopback sidecar, not to the token host. Where
  the token host's trust anchor narrowed (a `tls_ca_file`, an internal CA, or a `crl_file`), the
  opener it went through carried that host's CA and CRL, so an `https://` sidecar would have been
  verified against them. With the default system anchor it already used the shared opener. It now
  always uses the opener the REST destination's own ECH hop uses. The token hop's revocation
  refusal is unchanged.
