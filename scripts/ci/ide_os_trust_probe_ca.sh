#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Mint the disposable test CA and the 127.0.0.1 leaf it signs, for the IDE OS trust store probe
# (BACKLOG #4576; .github/workflows/ide-os-trust-probe.yml is the only caller).
#
# Usage: bash scripts/ci/ide_os_trust_probe_ca.sh <out-dir>
#
# Writes ca.pem, ca.cer (the same certificate as DER, for Windows' Import-Certificate), leaf.pem and
# leaf.key into <out-dir>, which must not exist yet. The CA's private key is deleted before this
# exits, so nothing that outlives the script can sign another certificate under the CA the job
# imports. Both certificates are valid for two days. Run it in CI only: the job imports ca.cer into
# the runner's OS store, and nothing here should ever be imported into a real machine's.
#
# Works with the OpenSSL on PATH in ubuntu-latest's bash and in windows-latest's Git Bash. The
# subjects come from config files rather than `-subj`, which Git Bash would rewrite as a path.
set -euo pipefail

out="${1:?usage: ide_os_trust_probe_ca.sh <out-dir>}"
mkdir "$out" # fails, and so stops the script, when it already exists
cd "$out"

cat > ca.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
[dn]
CN = MessageFoundry IDE OS trust probe disposable CA
[ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > leaf.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
[dn]
CN = 127.0.0.1
[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1, DNS:localhost
authorityKeyIdentifier = keyid
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -x509 -new -key ca.key -config ca.cnf -extensions ext -days 2 -out ca.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
openssl req -new -key leaf.key -config leaf.cnf -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile leaf.cnf -extensions ext -out leaf.pem
openssl x509 -in ca.pem -outform der -out ca.cer
rm -f ca.key ca.srl leaf.csr ca.cnf leaf.cnf

# The positive control for the certificates themselves: the leaf verifies under the CA alone.
openssl verify -CAfile ca.pem leaf.pem
