- **The `messagefoundry-toolkit` wheel is now signed, attested and licensed like the engine wheel.**
  The release job signs it with Sigstore, attaches its `.sigstore.json` bundle to the GitHub
  release, and adds it to the SLSA build-provenance subjects, so `gh attestation verify` works on
  it. The wheel now ships `LICENSE` and `NOTICE`. See
  [SUPPLY-CHAIN.md](../docs/SUPPLY-CHAIN.md). (`BACKLOG #1192`)
