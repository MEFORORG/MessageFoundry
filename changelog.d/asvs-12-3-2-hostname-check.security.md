- **`tls_check_hostname = false` is a recorded loosening now, never a silent one (ASVS 12.3.2).**
  The MLLP, FTPS, Email and Direct hops log a WARNING at each construction that names the connection
  and the host. `messagefoundry check` gains an advisory `tls-check-hostname` line, and
  `security_loosenings()`, and so `GET /security/posture`, gains a `tls_check_hostname` entry. On a
  first deployment the flag would have been accepted with no line anywhere on MLLP, on Email and
  Direct without credentials, and on a hand-built FTPS spec. It is not refused under
  `enforcement = enforce`, on the `tls_allow_expired` precedent. The `tls_allow_expired` WARNING,
  `check` line and registry entry no longer claim the hostname is verified on a hop that turns that
  check off. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
