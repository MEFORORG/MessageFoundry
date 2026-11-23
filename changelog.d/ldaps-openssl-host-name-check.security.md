- **The LDAPS bind to Active Directory now has OpenSSL check the domain controller's host name,
  during the handshake.** It had relied on ldap3's own check, which on Python 3.12 and later is a
  backport of the Python 3.4 matcher: it accepted a certificate named only in its subject common
  name or by a partial wildcard such as `l*.example.test`, and refused a domain controller dialled by
  IP address whose certificate names that address. The bind now refuses the first two and accepts
  the third.
