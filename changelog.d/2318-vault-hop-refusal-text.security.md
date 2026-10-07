- **A Vault hop refusal now reaches the operator in its own words, and it is one type at both
  phases.** The Vault KV secret provider, the store key provider and the Transit cipher used to
  shrink a refusal raised while sending, such as an `http://` Vault behind an `https://` proxy or a
  misframed reply, to a bare type name like `EgressReplyError`. They now keep the refusal's fixed
  text, which names no address, proxy URL, token or reply byte. Every other failure still gives
  its type name only. A refusal of the hop itself is now `InsecureHopRefused` whether it fires
  when the client is built or before a send; a refusal of the reply stays an `EgressReplyError`.
  The shared engine client (`messagefoundry.apiclient`) no longer sends through a proxy named by
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` or the system proxy settings. The configuration guide now
  says why the TLS leg to an `https://` proxy shares the Vault CA file, and why the proxy's CA must
  not be added to it. (`vault BACKLOG #2318`)
