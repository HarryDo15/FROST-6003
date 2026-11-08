# Decentralized Group Vault

Requires Docker running and Docker Compose installed. On Windows, use Git Bash.

From the project directory, run:

```sh
./run_demo.sh
```

This starts the coordinator and three nodes, then signs `Hello` using two nodes.
Approval is automatic. Success shows `"status": "completed"` and `"verified": true`.

Send another message:

```sh
export VAULT_UID=$(id -u) VAULT_GID=$(id -g)
MSYS_NO_PATHCONV=1 docker compose run --rm requester request \
  --config /config/requester.json --message 'Another message' --wait \
  --coordinator http://coordinator:8080 --allow-http
```

Stop the project:

```sh
VAULT_UID=$(id -u) VAULT_GID=$(id -g) docker compose down
```

Vault data stays in `.vault/`. Run `./run_demo.sh` again to restart.
