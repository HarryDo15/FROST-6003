#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

export VAULT_UID="$(id -u)"
export VAULT_GID="$(id -g)"
umask 077
mkdir -p .vault
if [ ! -f .vault/passphrase ]; then
    head -c 32 /dev/urandom | base64 > .vault/passphrase
fi

docker compose build
if [ ! -f .vault/setup/coordinator.json ]; then
    docker compose run --rm init
fi
docker compose up -d --wait --wait-timeout 60 coordinator node-1 node-2 node-3
docker compose run --rm requester
