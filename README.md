# Decentralized Group Vault

SE6003 Cryptography project: a vault whose secrets can only be recovered when a
threshold `t` of `n` group members cooperate.

## Layout

| Path                         | Purpose                                                    |
| ---------------------------- | ---------------------------------------------------------- |
| `group_vault/coordinator.py` | Service that orchestrates share distribution and recovery. |
| `group_vault/vault_cli.py`   | Member-facing command-line client.                         |
| `group_vault/crypto.py`      | Threshold primitives (Shamir's Secret Sharing).            |
| `group_vault/types.py`       | Domain types shared by the back end and API consumers.     |

## Development

Requires Python 3.11+.

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check . && ruff format --check .   # lint (CI requires 0 issues)
mypy group_vault                        # type check
```

## `group_vault.crypto`

```python
from group_vault.crypto import split_secret, combine_shares

shares = split_secret(b"my secret", t=3, n=5)  # any 3 of 5 shares recover it
secret = combine_shares(shares[:3])
```

Uses pycryptodome's Shamir's Secret Sharing on a random AES key, with the
secret itself encrypted under AES-GCM. Too few, corrupted or mixed shares raise
`SecretSharingError` instead of returning a wrong secret.
