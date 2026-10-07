"""Threshold secret sharing for the group vault.

Built on pycryptodome's Shamir's Secret Sharing, which splits 16-byte values.
To support secrets of any length, ``split_secret`` encrypts the secret with a
random AES-128 key (AES-GCM) and splits only that key. Each share is:

    version (1) | threshold (1) | index (1) | key share (16) | nonce | ciphertext | tag

Every share carries the same encrypted secret, so any ``t`` shares are enough
to recover it. With fewer than ``t`` shares the key, and therefore the secret,
stays hidden. AES-GCM authentication rejects corrupted or mismatched shares
instead of returning a wrong secret.
"""

from collections.abc import Sequence

from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

MIN_THRESHOLD = 2
MAX_SHARES = 255

_VERSION = 1
_HEADER_LEN = 3  # version, threshold, index
_KEY_LEN = 16
_NONCE_LEN = 12
_TAG_LEN = 16
_SEALED_OFFSET = _HEADER_LEN + _KEY_LEN
_MIN_SHARE_LEN = _SEALED_OFFSET + _NONCE_LEN + 1 + _TAG_LEN


class SecretSharingError(ValueError):
    """Raised when a secret cannot be split or reconstructed."""


def split_secret(secret: bytes, t: int, n: int) -> list[bytes]:
    """Split ``secret`` into ``n`` shares, any ``t`` of which recover it."""
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


def combine_shares(shares: Sequence[bytes]) -> bytes:
    """Recover the secret from at least ``t`` shares made by ``split_secret``."""
    if not shares:
        raise SecretSharingError("no shares provided")
    if any(len(s) < _MIN_SHARE_LEN or s[0] != _VERSION for s in shares):
        raise SecretSharingError("malformed share")

    threshold = shares[0][1]
    sealed = shares[0][_SEALED_OFFSET:]
    if any(s[1] != threshold or s[_SEALED_OFFSET:] != sealed for s in shares):
        raise SecretSharingError("shares do not belong to the same split")
    if len({s[2] for s in shares}) != len(shares):
        raise SecretSharingError("duplicate share")
    if len(shares) < threshold:
        raise SecretSharingError(f"not enough shares: have {len(shares)}, need {threshold}")

    key = Shamir.combine([(s[2], s[_HEADER_LEN:_SEALED_OFFSET]) for s in shares], ssss=False)
    nonce = sealed[:_NONCE_LEN]
    ciphertext = sealed[_NONCE_LEN:-_TAG_LEN]
    tag = sealed[-_TAG_LEN:]
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise SecretSharingError("shares are corrupted or have been tampered with") from exc
