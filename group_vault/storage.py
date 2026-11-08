"""Encrypted local storage for signer-node shares."""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

_FORMAT_VERSION = 2
_AAD = b"group-vault:encrypted-share-store:v2"
_COMPAT_AAD = b"group-vault:encrypted-share-store:v1"
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
_TAG_LEN = 16
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST_KIB = 65_536
_ARGON2_PARALLELISM = 1


class EncryptedShareStore:
    """Keep share records in one Argon2id-derived AES-GCM encrypted file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".vault" / "config.json"

    def exists(self) -> bool:
        """Return whether the encrypted store file exists."""

        return self.path.is_file()

    def store_share(
        self,
        vault_id: str,
        node_id: str,
        share: bytes,
        passphrase: str,
    ) -> None:
        """Encrypt and persist a share, replacing the matching vault/node record."""

        self._validate_identity(vault_id, node_id)
        if not share:
            raise ValueError("share must not be empty")
        if not passphrase:
            raise ValueError("passphrase must not be empty")

        records = self._read_records(passphrase) if self.exists() else []

        record = {
            "vault_id": vault_id,
            "node_id": node_id,
            "share": base64.b64encode(share).decode("ascii"),
        }
        records = [
            item for item in records if item["vault_id"] != vault_id or item["node_id"] != node_id
        ]
        records.append(record)
        self._write_encrypted(records, passphrase)

    def load_share(self, vault_id: str, node_id: str, passphrase: str) -> bytes:
        """Decrypt and return a share without printing or logging it."""

        self._validate_identity(vault_id, node_id)
        if not passphrase:
            raise ValueError("passphrase must not be empty")

        for record in self._read_records(passphrase):
            if record["vault_id"] == vault_id and record["node_id"] == node_id:
                try:
                    share = base64.b64decode(record["share"], validate=True)
                except (binascii.Error, TypeError, ValueError) as exc:
                    raise ValueError("stored share record is malformed") from exc
                if not share:
                    raise ValueError("stored share is empty")
                return share
        raise ValueError("no share matches that vault and node")

    def _write_encrypted(self, records: list[dict[str, str]], passphrase: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # A fresh salt derives a fresh AES key for every rewrite. The nonce is
        # also fresh; both values are stored beside the authenticated ciphertext.
        salt = get_random_bytes(_SALT_LEN)
        nonce = get_random_bytes(_NONCE_LEN)
        key = self._derive_key(passphrase, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_LEN)
        cipher.update(_AAD)
        ciphertext, tag = cipher.encrypt_and_digest(self._serialize(records))

        envelope = {
            "version": _FORMAT_VERSION,
            "kdf": "argon2id",
            "cipher": "aes-256-gcm",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }
        self._atomic_write(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))

    def _read_records(self, passphrase: str) -> list[dict[str, str]]:
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError("encrypted store is malformed")
            version = envelope.get("version")
            if type(version) is not int or version not in (1, _FORMAT_VERSION):
                raise ValueError("unsupported encrypted store version")
            if version == 1 and "tag" not in envelope:
                raise ValueError(
                    "legacy encrypted store format: use the original application "
                    "and passphrase to recover it; preserve the file as a backup"
                )
            if envelope.get("kdf") != "argon2id" or envelope.get("cipher") != "aes-256-gcm":
                raise ValueError("unsupported encrypted store algorithms")

            salt = self._decode_field(envelope, "salt", _SALT_LEN)
            nonce = self._decode_field(envelope, "nonce", _NONCE_LEN)
            ciphertext = self._decode_field(envelope, "ciphertext")
            tag = self._decode_field(envelope, "tag", _TAG_LEN)
            key = self._derive_key(passphrase, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_LEN)
            cipher.update(_COMPAT_AAD if version == 1 else _AAD)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as exc:
                raise ValueError("wrong passphrase or encrypted store was modified") from exc
            records: Any = json.loads(plaintext)
            if not isinstance(records, list):
                raise ValueError("encrypted store payload must be a list")

            checked_records: list[dict[str, str]] = []
            for item in records:
                if not isinstance(item, dict) or not all(
                    isinstance(item.get(field), str) for field in ("vault_id", "node_id", "share")
                ):
                    raise ValueError("encrypted store contains a malformed record")
                checked_records.append(item)
            return checked_records
        except (binascii.Error, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("encrypted store is malformed") from exc

    @staticmethod
    def _decode_field(
        envelope: dict[str, Any], field: str, expected_len: int | None = None
    ) -> bytes:
        value = envelope.get(field)
        if not isinstance(value, str):
            raise ValueError("encrypted store is malformed")
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("encrypted store is malformed") from exc
        if expected_len is not None and len(decoded) != expected_len:
            raise ValueError("encrypted store is malformed")
        return decoded

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST_KIB,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_KEY_LEN,
            type=Type.ID,
        )

    @staticmethod
    def _serialize(records: list[dict[str, str]]) -> bytes:
        return json.dumps(records, separators=(",", ":")).encode("utf-8")

    def _atomic_write(self, contents: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            if os.name != "nt":
                os.chmod(temporary_path, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(contents)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_path, self.path)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _validate_identity(vault_id: str, node_id: str) -> None:
        if not vault_id.strip() or not node_id.strip():
            raise ValueError("vault_id and node_id must not be empty")
