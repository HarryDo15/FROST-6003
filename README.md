# Decentralized Group Vault

SE6003 cryptography project. Requires Python 3.12+.

## Setup

```sh
pip install uv==0.13.6
uv sync --frozen --extra dev
uv run vault-coordinator
```

API documentation: http://127.0.0.1:8080/docs

## Node CLI

Create demo shares:

```sh
uv run vault-cli init --total 3 --threshold 2
```

The output contains the vault ID and each node's Base64 share. Store one share
using hidden input and a passphrase, then verify it:

```sh
uv run vault-cli store-share --vault-id <vault-id> --node-id 1
uv run vault-cli verify-share --vault-id <vault-id> --node-id 1
```

Shares are encrypted in `~/.vault/config.json`. Start a listener:

```sh
uv run vault-cli start --node-id 1 --coordinator http://127.0.0.1:8080
```

The listener displays pending requests and asks for local approval. Use `--observe`
to display requests without prompting, or `--auto-approve` for local automatic
approval. Approval does not submit shares or sign messages. Pending requests are
visible to every listener; node IDs are not authentication.

The coordinator combines two shares per request and expires pending requests after
five minutes. Run one worker; requests are stored in memory and lost on restart.

Currently supports Shamir share reconstruction. Message signing and node authentication
are not implemented. Do not submit private signing keys.

## Docker

```sh
docker build -t group-vault .
docker run --rm -p 127.0.0.1:8080:8080 group-vault
```

Build the node CLI image:

```sh
docker build -f Dockerfile.vault-cli -t vault-cli .
docker run --rm vault-cli --help
```

## Checks

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy group_vault
```
