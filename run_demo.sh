#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

export VAULT_UID="$(id -u)"
export VAULT_GID="$(id -g)"
compose=(docker compose -f docker-compose.yml)
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        compose+=(-f docker-compose.windows.yml)
        export MSYS_NO_PATHCONV=1
        ;;
esac

umask 077
mkdir -p .vault
if [ ! -f .vault/passphrase ]; then
    head -c 32 /dev/urandom | base64 > .vault/passphrase
fi

"${compose[@]}" build
if [ ! -f .vault/setup/coordinator.json ]; then
    "${compose[@]}" run --rm init
fi
"${compose[@]}" up -d --wait --wait-timeout 60 coordinator node-1 node-2 node-3
"${compose[@]}" run --rm requester
