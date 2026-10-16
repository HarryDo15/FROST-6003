import argparse
import base64
import json
import secrets
import sys
import uuid
from collections.abc import Sequence

from group_vault.crypto import MAX_SHARES, MIN_THRESHOLD, split_secret


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vault-cli")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a demo vault share set")
    init.add_argument("--total", "-n", type=int, required=True)
    init.add_argument("--threshold", "-t", type=int, required=True)

    args = parser.parse_args(argv)

    if not MIN_THRESHOLD <= args.threshold <= args.total <= MAX_SHARES:
        parser.error(f"require {MIN_THRESHOLD} <= threshold <= total <= {MAX_SHARES}")

    # Demo secret for testing the CLI; this is not a real asset key.
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
        "Warning: the output contains sensitive shares. "
        "Use only demo data until secure storage is integrated.",
        file=sys.stderr,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
