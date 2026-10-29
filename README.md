# Decentralized Group Vault

SE6003 cryptography project. Requires Python 3.12+.

## Setup

```sh
pip install uv==0.13.6
uv sync --frozen --extra dev
uv run vault-coordinator
```

API documentation: http://127.0.0.1:8080/docs

The coordinator combines two shares per request and expires pending requests after
five minutes. Run one worker; requests are stored in memory and lost on restart.

Currently supports Shamir share reconstruction. Message signing and node authentication
are not implemented. Do not submit private signing keys.

## Docker

```sh
docker build -t group-vault .
docker run --rm -p 127.0.0.1:8080:8080 group-vault
```

## Checks

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy group_vault
```
