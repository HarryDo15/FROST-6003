"""FROST(Ed25519, SHA-512), RFC 9591, using libsodium curve/scalar operations."""

import base64
import binascii
import hashlib
import json
import secrets
from typing import Any

from nacl import bindings
from nacl.exceptions import BadSignatureError
from nacl.exceptions import RuntimeError as SodiumError
from nacl.signing import VerifyKey


class CryptoError(ValueError):
    pass


_ORDER = 2**252 + 27742317777372353535851937790883648493
_CONTEXT = b"FROST-ED25519-SHA512-v1"
_IDENTITY = b"\x01" + bytes(31)
_ZERO = bytes(32)
_FORMAT = "frost-python-v1"
_add = bindings.crypto_core_ed25519_scalar_add
_mul = bindings.crypto_core_ed25519_scalar_mul
_point_add = bindings.crypto_core_ed25519_add


def _scalar(value: int) -> bytes:
    return (value % _ORDER).to_bytes(32, "little")


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decoded(value: str, length: int | None = None) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > 131072:
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        if _encoded(raw) != value or (length is not None and len(raw) != length):
            raise ValueError
        return raw
    except (ValueError, binascii.Error) as exc:
        raise CryptoError("invalid FROST encoding") from exc


def _pack(kind: str, **values: Any) -> str:
    data = {"format": _FORMAT, "kind": kind, **values}
    return _encoded(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise CryptoError("duplicate FROST field")
        result[name] = value
    return result


def _unpack(value: str, kind: str, fields: set[str]) -> dict[str, Any]:
    try:
        data = json.loads(_decoded(value), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CryptoError(
            "unsupported or invalid FROST package; initialize a new vault in a new directory"
        ) from exc
    if not isinstance(data, dict) or data.get("format") != _FORMAT:
        raise CryptoError("unsupported FROST package; initialize a new vault in a new directory")
    if data.get("kind") != kind or set(data) != fields | {"format", "kind"}:
        raise CryptoError("invalid FROST package fields")
    return data


def _hex(value: Any) -> bytes:
    try:
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError
        raw = bytes.fromhex(value)
        if raw.hex() != value:
            raise ValueError
        return raw
    except ValueError as exc:
        raise CryptoError("invalid FROST scalar or point encoding") from exc


def _read_scalar(value: Any, *, nonzero: bool = False) -> bytes:
    raw = _hex(value)
    if int.from_bytes(raw, "little") >= _ORDER or (nonzero and raw == _ZERO):
        raise CryptoError("invalid FROST scalar")
    return raw


def _point(value: Any) -> bytes:
    raw = _hex(value)
    if not bindings.crypto_core_ed25519_is_valid_point(raw):
        raise CryptoError("invalid FROST point")
    # Check subgroup membership explicitly, including with older libsodium builds.
    try:
        multiple = bindings.crypto_scalarmult_ed25519_noclamp(_scalar(_ORDER - 1), raw)
        if _point_add(multiple, raw) != _IDENTITY:
            raise CryptoError("FROST point is outside the prime-order subgroup")
    except SodiumError as exc:
        raise CryptoError("invalid FROST point") from exc
    return raw


def _base(scalar: bytes) -> bytes:
    return _IDENTITY if scalar == _ZERO else bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)


def _point_mul(scalar: bytes, point: bytes) -> bytes:
    if scalar == _ZERO or point == _IDENTITY:
        return _IDENTITY
    return bindings.crypto_scalarmult_ed25519_noclamp(scalar, point)


def _parameters(threshold: Any, total: Any) -> None:
    if type(threshold) is not int or type(total) is not int or not 2 <= threshold <= total <= 255:
        raise CryptoError("need 2 <= threshold <= total <= 255")


def _identifier(value: Any, total: int) -> int:
    if not isinstance(value, str) or value not in {str(i) for i in range(1, total + 1)}:
        raise CryptoError("invalid FROST participant identifier")
    return int(value)


def _key(value: str) -> dict[str, Any]:
    key = _unpack(value, "key", {"node_id", "threshold", "total", "public_key", "secret"})
    _parameters(key["threshold"], key["total"])
    _identifier(key["node_id"], key["total"])
    _point(key["public_key"])
    _read_scalar(key["secret"], nonzero=True)
    return key


def _public(value: str) -> dict[str, Any]:
    public = _unpack(value, "public", {"threshold", "total", "coefficients"})
    _parameters(public["threshold"], public["total"])
    coefficients = public["coefficients"]
    if not isinstance(coefficients, list) or len(coefficients) != public["threshold"]:
        raise CryptoError("invalid FROST public polynomial")
    for coefficient in coefficients:
        _point(coefficient)
    return public


def _public_share(public: dict[str, Any], identifier: int) -> bytes:
    result = _IDENTITY
    for coefficient in reversed(public["coefficients"]):
        result = _point_add(_point_mul(_scalar(identifier), result), _point(coefficient))
    if result == _IDENTITY:
        raise CryptoError("invalid FROST public share")
    return result


def _hash_scalar(message: bytes) -> bytes:
    return bindings.crypto_core_ed25519_scalar_reduce(hashlib.sha512(message).digest())


def _nonce(secret: bytes) -> bytes:
    while True:
        nonce = _hash_scalar(_CONTEXT + b"nonce" + secrets.token_bytes(32) + secret)
        if nonce != _ZERO:
            return nonce


def _commitment(value: str) -> tuple[bytes, bytes]:
    pair = _unpack(value, "commitment", {"hiding", "binding"})
    return _point(pair["hiding"]), _point(pair["binding"])


def _lagrange(identifier: int, identifiers: list[int]) -> bytes:
    numerator, denominator = 1, 1
    for other in identifiers:
        if other != identifier:
            numerator = numerator * other % _ORDER
            denominator = denominator * (other - identifier) % _ORDER
    return _scalar(numerator * pow(denominator, -1, _ORDER))


def _signing_data(
    message: bytes, commitments: dict[str, str], public_key: bytes, threshold: int, total: int
) -> tuple[dict[int, tuple[bytes, bytes]], dict[int, bytes], bytes, bytes]:
    if not isinstance(message, bytes) or len(message) > 65536:
        raise CryptoError("invalid FROST message")
    if not isinstance(commitments, dict) or not threshold <= len(commitments) <= total:
        raise CryptoError("insufficient or invalid FROST participants")
    pairs = {_identifier(node, total): _commitment(value) for node, value in commitments.items()}
    pairs = dict(sorted(pairs.items()))
    encoded = b"".join(
        _scalar(node) + hiding + binding for node, (hiding, binding) in pairs.items()
    )
    prefix = (
        public_key
        + hashlib.sha512(_CONTEXT + b"msg" + message).digest()
        + hashlib.sha512(_CONTEXT + b"com" + encoded).digest()
    )
    factors = {node: _hash_scalar(_CONTEXT + b"rho" + prefix + _scalar(node)) for node in pairs}
    group_commitment = _IDENTITY
    for node, (hiding, binding) in pairs.items():
        group_commitment = _point_add(
            group_commitment, _point_add(hiding, _point_mul(factors[node], binding))
        )
    if group_commitment == _IDENTITY:
        raise CryptoError("invalid FROST group commitment; start a new signing request")
    challenge = _hash_scalar(group_commitment + public_key + message)
    return pairs, factors, group_commitment, challenge


def generate_keys(threshold: int, total: int) -> dict[str, Any]:
    _parameters(threshold, total)
    while True:
        coefficients = [_scalar(secrets.randbelow(_ORDER - 1) + 1) for _ in range(threshold)]
        shares = {}
        for node in range(1, total + 1):
            share = _ZERO
            for coefficient in reversed(coefficients):
                share = _add(_mul(share, _scalar(node)), coefficient)
            shares[str(node)] = share
        if all(share != _ZERO for share in shares.values()):
            break
    public_key = _base(coefficients[0])
    public = _pack(
        "public",
        threshold=threshold,
        total=total,
        coefficients=[_base(c).hex() for c in coefficients],
    )
    packages = {
        node: _pack(
            "key",
            node_id=node,
            threshold=threshold,
            total=total,
            public_key=public_key.hex(),
            secret=share.hex(),
        )
        for node, share in shares.items()
    }
    return {
        "public_key_package": public,
        "verifying_key": _encoded(public_key),
        "key_packages": packages,
    }


def create_commitment(key_package: str) -> tuple[str, str]:
    key = _key(key_package)
    secret = _read_scalar(key["secret"], nonzero=True)
    hiding, binding = _nonce(secret), _nonce(secret)
    return (
        _pack("nonces", hiding=hiding.hex(), binding=binding.hex()),
        _pack("commitment", hiding=_base(hiding).hex(), binding=_base(binding).hex()),
    )


def sign_share(key_package: str, nonces: str, message: bytes, commitments: dict[str, str]) -> str:
    key = _key(key_package)
    nonce_pair = _unpack(nonces, "nonces", {"hiding", "binding"})
    hiding = _read_scalar(nonce_pair["hiding"], nonzero=True)
    binding = _read_scalar(nonce_pair["binding"], nonzero=True)
    pairs, factors, _, challenge = _signing_data(
        message, commitments, _point(key["public_key"]), key["threshold"], key["total"]
    )
    node = int(key["node_id"])
    if pairs.get(node) != (_base(hiding), _base(binding)):
        raise CryptoError("FROST commitment does not match this signer's nonces")
    weight = _mul(_lagrange(node, list(pairs)), challenge)
    share = _add(
        _add(hiding, _mul(binding, factors[node])), _mul(weight, _read_scalar(key["secret"]))
    )
    return _encoded(share)


def aggregate(
    message: bytes,
    commitments: dict[str, str],
    shares: dict[str, str],
    public_key_package: str,
) -> str:
    public = _public(public_key_package)
    if (
        not isinstance(commitments, dict)
        or not isinstance(shares, dict)
        or set(shares) != set(commitments)
    ):
        raise CryptoError("FROST shares must match all committed participants")
    pairs, factors, group_commitment, challenge = _signing_data(
        message,
        commitments,
        _point(public["coefficients"][0]),
        public["threshold"],
        public["total"],
    )
    total = _ZERO
    for node, (hiding, binding) in pairs.items():
        share = _read_scalar(_decoded(shares[str(node)], 32).hex())
        weight = _mul(challenge, _lagrange(node, list(pairs)))
        expected = _point_add(
            _point_add(hiding, _point_mul(factors[node], binding)),
            _point_mul(weight, _public_share(public, node)),
        )
        if _base(share) != expected:
            raise CryptoError(f"invalid FROST signature share from participant {node}")
        total = _add(total, share)
    signature = _encoded(group_commitment + total)
    if not verify(message, signature, public_key_package):
        raise CryptoError("invalid aggregate FROST signature")
    return signature


def verify(message: bytes, signature: str, public_key_package: str) -> bool:
    try:
        public = _public(public_key_package)
        raw = _decoded(signature, 64)
        _point(raw[:32].hex())
        _read_scalar(raw[32:].hex())
        VerifyKey(_point(public["coefficients"][0])).verify(message, raw)
        return True
    except (CryptoError, BadSignatureError, TypeError, ValueError):
        return False


def validate_commitment(commitment: str) -> None:
    _commitment(commitment)


def validate_key_package(key_package: str, node_id: str, public_key_package: str) -> None:
    key, public = _key(key_package), _public(public_key_package)
    node = _identifier(node_id, public["total"])
    if (
        key["node_id"] != node_id
        or key["threshold"] != public["threshold"]
        or key["total"] != public["total"]
        or key["public_key"] != public["coefficients"][0]
        or _base(_read_scalar(key["secret"])) != _public_share(public, node)
    ):
        raise CryptoError("FROST key share does not match the vault")


def validate_vault(public_key_package: str, threshold: int, total: int, verifying_key: str) -> None:
    public = _public(public_key_package)
    _parameters(threshold, total)
    if (
        threshold != public["threshold"]
        or total != public["total"]
        or _decoded(verifying_key, 32) != _point(public["coefficients"][0])
    ):
        raise CryptoError("FROST public key does not match the vault")
    for node in range(1, total + 1):
        _public_share(public, node)
