module messagefoundry.dev/ech-sidecar

// stdlib-only, no dependencies — builds offline with GOPROXY=off.
// Requires Go >= 1.26 for crypto/tls Encrypted Client Hello
// (tls.Config.EncryptedClientHelloConfigList + ConnectionState.ECHAccepted).
go 1.26
