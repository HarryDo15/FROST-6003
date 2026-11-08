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
from typing import NoReturn

from group_vault.crypto import MAX_SHARES, MIN_THRESHOLD, split_secret
from group_vault.daemon import run_daemon
from group_vault.storage import EncryptedShareStore
from group_vault.terminal import show_status


class CLIParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        show_status("REJECTED", message)
        self.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    parser = CLIParser(prog="vault-cli")
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
    start = commands.add_parser("start", help="Poll and authorize requests locally")
    start.add_argument("--node-id", required=True)
    start.add_argument("--coordinator", required=True)
    start.add_argument("--poll-interval", type=float, default=2.0)
    start.add_argument("--timeout", type=float, default=5.0)
    start.add_argument("--once", action="store_true", help="Poll once and exit")
    mode = start.add_mutually_exclusive_group()
    mode.add_argument("--auto-approve", action="store_true", help="Authorize without stdin")
    mode.add_argument(
        "--observe", action="store_true", help="Display requests without authorization"
    )
    return parser


def _store_share(vault_id: str, node_id: str) -> int:
    encoded_share = getpass.getpass("Base64 share (input hidden): ").strip()
    try:
        share = base64.b64decode(encoded_share, validate=True)
    except ValueError:
        show_status("REJECTED", "Error: share must be valid Base64.")
        return 1
    if not share:
        show_status("REJECTED", "Error: share must not be empty.")
        return 1

    store = EncryptedShareStore()
    passphrase = getpass.getpass("Vault passphrase: ")
    if not passphrase:
        show_status("REJECTED", "Error: passphrase must not be empty.")
        return 1
    if not store.exists():
        confirmation = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirmation:
            show_status("REJECTED", "Error: passphrases do not match.")
            return 1

    try:
        store.store_share(vault_id, node_id, share, passphrase)
    except (OSError, ValueError) as exc:
        show_status("REJECTED", f"Error: could not store share: {exc}")
        return 1
    print(f"Encrypted share saved for vault {vault_id}, node {node_id}.")
    return 0


def _verify_share(vault_id: str, node_id: str) -> int:
    store = EncryptedShareStore()
    passphrase = getpass.getpass("Vault passphrase: ")
    try:
        share = store.load_share(vault_id, node_id, passphrase)
    except (OSError, ValueError) as exc:
        show_status("REJECTED", f"Error: could not verify share: {exc}")
        return 1
    if not share:
        show_status("REJECTED", "Error: stored share is empty.")
        return 1
    print(f"Encrypted share verified for vault {vault_id}, node {node_id}.")
    return 0


def _run(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "start":
        try:
            return run_daemon(
                args.coordinator,
                args.node_id,
                args.poll_interval,
                args.timeout,
                args.once,
                interactive=not args.observe,
                auto_approve=args.auto_approve,
            )
        except ValueError as exc:
            parser.error(str(exc))

    if args.command == "init":
        if not MIN_THRESHOLD <= args.threshold <= args.total <= MAX_SHARES:
            parser.error(f"require {MIN_THRESHOLD} <= threshold <= total <= {MAX_SHARES}")
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
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(argv)
    except (EOFError, KeyboardInterrupt):
        show_status("REJECTED", "Command cancelled")
        return 1
    except (OSError, ValueError) as exc:
        show_status("REJECTED", str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
