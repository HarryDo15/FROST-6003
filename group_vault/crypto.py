from collections.abc import Sequence

from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

MIN_THRESHOLD = 2
MAX_SHARES = 255

_VERSION = 1
_HEADER_LEN = 3
_KEY_LEN = 16
_NONCE_LEN = 12
_TAG_LEN = 16
_SEALED_OFFSET = _HEADER_LEN + _KEY_LEN
_MIN_SHARE_LEN = _SEALED_OFFSET + _NONCE_LEN + 1 + _TAG_LEN


class SecretSharingError(ValueError):
    pass


def split_secret(secret: bytes, t: int, n: int) -> list[bytes]:
    if not secret:
        raise SecretSharingError("secret must not be empty")
    if not MIN_THRESHOLD <= t <= n <= MAX_SHARES:
        raise SecretSharingError(f"need {MIN_THRESHOLD} <= t <= n <= {MAX_SHARES}, got t={t} n={n}")

    key = get_random_bytes(_KEY_LEN)
    nonce = get_random_bytes(_NONCE_LEN)
    ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(secret)
    sealed = nonce + ciphertext + tag

    return [
        bytes([_VERSION, t, index]) + key_share + sealed
        for index, key_share in Shamir.split(t, n, key, ssss=False)
    ]


def validate_shares(shares: Sequence[bytes]) -> None:
    if not shares:
        raise SecretSharingError("no shares provided")
    if any(len(s) < _MIN_SHARE_LEN or s[0] != _VERSION for s in shares):
        raise SecretSharingError("malformed share")

    threshold = shares[0][1]
    if threshold < MIN_THRESHOLD or any(s[2] == 0 for s in shares):
        raise SecretSharingError("invalid threshold or share index")
    sealed = shares[0][_SEALED_OFFSET:]
    if any(s[1] != threshold or s[_SEALED_OFFSET:] != sealed for s in shares):
        raise SecretSharingError("shares do not belong to the same split")
    if len({s[2] for s in shares}) != len(shares):
        raise SecretSharingError("duplicate share")


def combine_shares(shares: Sequence[bytes]) -> bytes:
    validate_shares(shares)
    threshold = shares[0][1]
    if len(shares) < threshold:
        raise SecretSharingError(f"not enough shares: have {len(shares)}, need {threshold}")

    key = Shamir.combine([(s[2], s[_HEADER_LEN:_SEALED_OFFSET]) for s in shares], ssss=False)
    sealed = shares[0][_SEALED_OFFSET:]
    nonce = sealed[:_NONCE_LEN]
    ciphertext = sealed[_NONCE_LEN:-_TAG_LEN]
    tag = sealed[-_TAG_LEN:]
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise SecretSharingError("shares are corrupted or have been tampered with") from exc
