#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Make a throwaway TLS server certificate for a CI database container: <dir>/server.pem and
# <dir>/server.key.
#
# WHY: the engine refuses a store login over trust_server_certificate=true or encrypt=false at
# every posture, and so does a SQL Server DATABASE connection login (owner ruling 2026-11-14,
# vault BACKLOG #3533 item 2). So a CI database must serve a certificate the engine can verify.
# The legs pin this file, or add it to the runner's trust store, and never weaken TLS.
#
# The shape is the strict-encryption pin test's (vault BACKLOG #3714 item 6, in ci.yml): Server
# Authentication EKU, CN and SAN localhost and 127.0.0.1, valid for 7 days from now. CA:FALSE, so
# a leg that trusts it adds a leaf to the runner's store and not an issuer that could sign for any
# host. A config file rather than -addext, so no OpenSSL default section adds a second
# basicConstraints, and no -subj, which Git Bash on Windows would rewrite as a path.
#
# The key is 0600 and the certificate 0644: the engine refuses a [store].ssl_root_cert file a
# group or world principal can write, at [security].enforcement = enforce.
#
# Usage: bash scripts/ci/db-tls-cert.sh <dir>
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <dir>" >&2
  exit 2
fi
dir="$1"
mkdir -p "$dir"
printf '%s\n' \
  '[req]' 'distinguished_name = dn' 'x509_extensions = ext' 'prompt = no' \
  '[dn]' 'CN = localhost' \
  '[ext]' 'basicConstraints = critical,CA:FALSE' \
  'subjectAltName = DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage = serverAuth' \
  > "$dir/req.cnf"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 7 -config "$dir/req.cnf" \
  -keyout "$dir/server.key" -out "$dir/server.pem"
chmod 600 "$dir/server.key"
chmod 644 "$dir/server.pem"
openssl x509 -in "$dir/server.pem" -noout -subject -dates \
  -ext basicConstraints,subjectAltName,extendedKeyUsage
