# Decentralized Group Vault

SE6003 Cryptography project.

## Setup

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy group_vault
```
