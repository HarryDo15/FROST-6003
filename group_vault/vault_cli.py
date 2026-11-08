import argparse
import base64
import getpass
import json
import secrets
import shutil
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from group_vault.client import CoordinatorClient, CoordinatorError
from group_vault.config import (
    CoordinatorConfig,
    NodeConfig,
    PublicVault,
    RequesterConfig,
    load_config,
    token_hash,
    write_config,
)
from group_vault.daemon import run_daemon
from group_vault.frost import generate_keys, validate_key_package, verify
from group_vault.storage import EncryptedShareStore


def passphrase(path: Path | None, confirm: bool = False) -> str:
    if path is not None:
        if path.stat().st_mode & 0o077:
            raise ValueError("passphrase file must be private: chmod 600 the file")
        value = path.read_text().rstrip("\r\n")
    else:
        value = getpass.getpass("Vault passphrase: ")
        if confirm and value != getpass.getpass("Confirm passphrase: "):
            raise ValueError("passphrases do not match")
    if not value:
        raise ValueError("passphrase must not be empty")
    return value


def initialize(directory: Path, threshold: int, total: int, password: str) -> None:
    if not 2 <= threshold <= total <= 255:
        raise ValueError("require 2 <= threshold <= total <= 255")
    if directory.exists():
        raise ValueError("output directory already exists; choose a new directory")
    keys = generate_keys(threshold, total)
    vault = PublicVault(
        vault_id=uuid.uuid4().hex,
        threshold=threshold,
        total=total,
        public_key_package=keys["public_key_package"],
        verifying_key=keys["verifying_key"],
    )
    requester_token = secrets.token_hex(32)
    node_tokens = {str(i): secrets.token_hex(32) for i in range(1, total + 1)}
    directory.mkdir(mode=0o700, parents=True)
    try:
        write_config(directory / "public.json", vault)
        write_config(
            directory / "requester.json", RequesterConfig(vault=vault, token=requester_token)
        )
        write_config(
            directory / "coordinator.json",
            CoordinatorConfig(
                vault=vault,
                requester_token_hash=token_hash(requester_token),
                node_token_hashes={node: token_hash(token) for node, token in node_tokens.items()},
            ),
        )
        for node_id, token in node_tokens.items():
            node_dir = directory / f"node-{node_id}"
            node_dir.mkdir(mode=0o700)
            config = NodeConfig(vault=vault, node_id=node_id, token=token)
            key_package = keys["key_packages"][node_id]
            validate_key_package(key_package, node_id, vault.public_key_package)
            EncryptedShareStore(node_dir / config.share_store).store_share(
                vault.vault_id, node_id, base64.b64decode(key_package, validate=True), password
            )
            write_config(node_dir / "config.json", config)
    except Exception:
        shutil.rmtree(directory)
        raise
    print(f"Created {threshold}-of-{total} FROST vault in {directory}")


def load_key(config_path: Path, config: NodeConfig, password: str) -> str:
    key = EncryptedShareStore(config_path.parent / config.share_store).load_share(
        config.vault.vault_id, config.node_id, password
    )
    encoded = base64.b64encode(key).decode()
    validate_key_package(encoded, config.node_id, config.vault.public_key_package)
    return encoded


def _message(args: argparse.Namespace) -> bytes:
    message: bytes = args.message_file.read_bytes() if args.message_file else args.message.encode()
    if not 1 <= len(message) <= 65536:
        raise ValueError("message must contain between 1 and 65536 bytes")
    return message


def show_result(
    client: CoordinatorClient,
    config: RequesterConfig,
    request_id: str,
    message: bytes,
    wait: bool,
) -> int:
    deadline = time.monotonic() + 310
    while True:
        result = client.result(request_id)
        if result.vault_id != config.vault.vault_id or result.request_id != request_id:
            raise ValueError("result belongs to a different vault or request")
        if base64.b64decode(result.payload_to_sign_base64, validate=True) != message:
            raise ValueError("result does not match the requested message")
        if result.status == "completed":
            if not result.signature_base64 or not verify(
                message, result.signature_base64, config.vault.public_key_package
            ):
                raise ValueError("signature verification failed")
            print(json.dumps({**result.model_dump(), "verified": True}))
            return 0
        if result.status not in ("pending", "signing") or not wait:
            print(result.model_dump_json())
            return 2 if result.status in ("pending", "signing") else 1
        if time.monotonic() >= deadline:
            raise TimeoutError("request did not finish within 310 seconds")
        time.sleep(0.5)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault-cli")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a FROST vault using a trusted dealer")
    init.add_argument("--total", "-n", type=int, required=True)
    init.add_argument("--threshold", "-t", type=int, required=True)
    init.add_argument("--output-dir", type=Path, required=True)
    init.add_argument("--passphrase-file", type=Path)
    start = commands.add_parser("start", help="Approve and sign requests as one node")
    start.add_argument("--config", type=Path, required=True)
    start.add_argument("--passphrase-file", type=Path)
    start.add_argument("--poll-interval", type=float, default=1.0)
    start.add_argument("--once", action="store_true")
    modes = start.add_mutually_exclusive_group()
    modes.add_argument("--observe", action="store_true")
    modes.add_argument("--auto-approve", action="store_true")
    check = commands.add_parser("verify-share", help="Decrypt and validate a node's key package")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--passphrase-file", type=Path)
    for name in ("request", "result"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        message = command.add_mutually_exclusive_group(required=True)
        message.add_argument("--message")
        message.add_argument("--message-file", type=Path)
        command.add_argument("--wait", action="store_true")
        if name == "request":
            command.add_argument("--requested-by", default="local-user")
        else:
            command.add_argument("--request-id", required=True)
    for command in (start, commands.choices["request"], commands.choices["result"]):
        command.add_argument("--coordinator", default="http://127.0.0.1:8080")
        command.add_argument("--timeout", type=float, default=5.0)
        command.add_argument(
            "--allow-http",
            action="store_true",
            help="Allow plain HTTP on a trusted private network",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            initialize(
                args.output_dir,
                args.threshold,
                args.total,
                passphrase(args.passphrase_file, confirm=True),
            )
            return 0
        if args.command in ("start", "verify-share"):
            node = load_config(args.config, NodeConfig)
            key = None
            if args.command == "verify-share" or not args.observe:
                key = load_key(args.config, node, passphrase(args.passphrase_file))
            if args.command == "verify-share":
                print("Encrypted FROST key package verified")
                return 0
            return run_daemon(
                args.coordinator,
                node,
                key,
                args.poll_interval,
                args.timeout,
                args.once,
                interactive=not args.observe,
                auto_approve=args.auto_approve,
                allow_http=args.allow_http,
            )
        requester = load_config(args.config, RequesterConfig)
        client = CoordinatorClient(
            args.coordinator, requester.token, args.timeout, allow_http=args.allow_http
        )
        message = _message(args)
        if args.command == "request":
            created = client.create_request(requester.vault.vault_id, message, args.requested_by)
            if not args.wait:
                print(created.model_dump_json())
                return 0
            request_id = created.request_id
            print(f"Waiting for {request_id}", file=sys.stderr)
        else:
            request_id = args.request_id
        return show_result(client, requester, request_id, message, args.wait)
    except (OSError, ValueError, CoordinatorError) as exc:
        print(f"vault-cli: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Command cancelled", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
