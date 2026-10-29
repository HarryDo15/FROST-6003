"""Command line tools for signer nodes."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import secrets
import sys
import uuid
from collections.abc import Sequence

from group_vault.crypto import MAX_SHARES, MIN_THRESHOLD, split_secret
from group_vault.storage import EncryptedShareStore


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault-cli")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a demo vault share set")
    init.add_argument("--total", "-n", type=int, required=True)
    init.add_argument("--threshold", "-t", type=int, required=True)

    store = commands.add_parser("store-share", help="Encrypt and save one node share")
    store.add_argument("--vault-id", required=True)
    store.add_argument("--node-id", required=True)

    verify = commands.add_parser("verify-share", help="Check a stored share")
    verify.add_argument("--vault-id", required=True)
    verify.add_argument("--node-id", required=True)
    return parser


def _store_share(vault_id: str, node_id: str) -> int:
    encoded_share = getpass.getpass("Base64 share (input hidden): ").strip()
    try:
        share = base64.b64decode(encoded_share, validate=True)
    except ValueError:
        print("Error: share must be valid Base64.", file=sys.stderr)
        return 2
    if not share:
        print("Error: share must not be empty.", file=sys.stderr)
        return 2

    store = EncryptedShareStore()
    passphrase = getpass.getpass("Vault passphrase: ")
    if not passphrase:
        print("Error: passphrase must not be empty.", file=sys.stderr)
        return 2
    if not store.exists():
        confirmation = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirmation:
            print("Error: passphrases do not match.", file=sys.stderr)
            return 2

    try:
        store.store_share(vault_id, node_id, share, passphrase)
    except (OSError, ValueError) as exc:
        print(f"Error: could not store share: {exc}", file=sys.stderr)
        return 1
    print(f"Encrypted share saved for vault {vault_id}, node {node_id}.")
    return 0


def _verify_share(vault_id: str, node_id: str) -> int:
    store = EncryptedShareStore()
    passphrase = getpass.getpass("Vault passphrase: ")
    try:
        share = store.load_share(vault_id, node_id, passphrase)
    except (OSError, ValueError) as exc:
        print(f"Error: could not verify share: {exc}", file=sys.stderr)
        return 1
    if not share:
        print("Error: stored share is empty.", file=sys.stderr)
        return 1
    print(f"Encrypted share verified for vault {vault_id}, node {node_id}.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        if not MIN_THRESHOLD <= args.threshold <= args.total <= MAX_SHARES:
            parser.error(
                f"require {MIN_THRESHOLD} <= threshold <= total <= {MAX_SHARES}"
            )
        demo_secret = secrets.token_bytes(32)
        shares = split_secret(demo_secret, args.threshold, args.total)
        result = {
            "vault_id": str(uuid.uuid4()),
            "total": args.total,
            "threshold": args.threshold,
            "shares": [
                {
                    "node_id": share[2],
                    "share_base64": base64.b64encode(share).decode("ascii"),
                }
                for share in shares
            ],
        }
        print(
            "Warning: output contains sensitive demo shares; "
            "do not use a real secret with this command.",
            file=sys.stderr,
        )
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "store-share":
        return _store_share(args.vault_id, args.node_id)

    if args.command == "verify-share":
        return _verify_share(args.vault_id, args.node_id)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
