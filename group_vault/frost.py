import base64
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class CryptoError(ValueError):
    pass


def _bridge() -> str:
    configured = os.environ.get("FROST_BRIDGE")
    if configured:
        return configured
    local = Path(__file__).resolve().parent.parent / "rust/frost_bridge/target/release/frost-bridge"
    if local.is_file():
        return str(local)
    installed = shutil.which("frost-bridge")
    if installed:
        return installed
    raise CryptoError("FROST bridge not found; build it first or set FROST_BRIDGE")


def _call(operation: str, **values: Any) -> dict[str, Any]:
    payload = json.dumps({"operation": operation, **values}).encode()
    if len(payload) > 4_194_304:
        raise CryptoError("FROST request exceeds size limit")
    try:
        result = subprocess.run(
            [_bridge()], input=payload, capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CryptoError("FROST bridge could not run") from exc
    if result.returncode:
        raise CryptoError("invalid FROST operation or cryptographic input")
    if len(result.stdout) > 4_194_304:
        raise CryptoError("FROST response exceeds size limit")
    try:
        response = json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise CryptoError("invalid FROST bridge response") from exc
    if not isinstance(response, dict) or "error" in response:
        raise CryptoError("invalid FROST bridge response")
    return response


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _string(response: dict[str, Any], field: str) -> str:
    value = response.get(field)
    if not isinstance(value, str):
        raise CryptoError("invalid FROST bridge response")
    return value


def generate_keys(threshold: int, total: int) -> dict[str, Any]:
    if not 2 <= threshold <= total <= 255:
        raise CryptoError("need 2 <= threshold <= total <= 255")
    result = _call("keygen", threshold=threshold, total=total)
    _string(result, "public_key_package")
    _string(result, "verifying_key")
    packages = result.get("key_packages")
    if (
        not isinstance(packages, dict)
        or set(packages) != {str(node) for node in range(1, total + 1)}
        or any(not isinstance(value, str) for value in packages.values())
    ):
        raise CryptoError("invalid FROST bridge response")
    return result


def create_commitment(key_package: str) -> tuple[str, str]:
    result = _call("commit", key_package=key_package)
    return _string(result, "nonces"), _string(result, "commitment")


def sign_share(key_package: str, nonces: str, message: bytes, commitments: dict[str, str]) -> str:
    return _string(
        _call(
            "sign",
            key_package=key_package,
            nonces=nonces,
            message=_encoded(message),
            commitments=commitments,
        ),
        "share",
    )


def aggregate(
    message: bytes,
    commitments: dict[str, str],
    shares: dict[str, str],
    public_key_package: str,
) -> str:
    return _string(
        _call(
            "aggregate",
            message=_encoded(message),
            commitments=commitments,
            shares=shares,
            public_key_package=public_key_package,
        ),
        "signature",
    )


def verify(message: bytes, signature: str, public_key_package: str) -> bool:
    try:
        result = _call(
            "verify",
            message=_encoded(message),
            signature=signature,
            public_key_package=public_key_package,
        )
    except CryptoError:
        return False
    return result.get("valid") is True


def validate_commitment(commitment: str) -> None:
    _call("validate_commitment", commitment=commitment)


def validate_key_package(key_package: str, node_id: str, public_key_package: str) -> None:
    _call(
        "validate_key_package",
        key_package=key_package,
        node_id=node_id,
        public_key_package=public_key_package,
    )


def validate_vault(public_key_package: str, threshold: int, total: int, verifying_key: str) -> None:
    _call(
        "validate_vault",
        public_key_package=public_key_package,
        threshold=threshold,
        total=total,
        verifying_key=verifying_key,
    )
