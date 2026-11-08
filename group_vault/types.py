"""Pending requests received from the coordinator."""

from __future__ import annotations

import base64
from dataclasses import dataclass


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{name} must be a nonempty string of at most 128 characters")
    return value


@dataclass(frozen=True)
class SignatureRequest:
    request_id: str
    vault_id: str
    requested_by: str
    message: bytes

    @classmethod
    def from_json(cls, value: object) -> SignatureRequest:
        if not isinstance(value, dict):
            raise ValueError("request must be an object")
        request_id = _identifier(value.get("request_id"), "request_id")
        vault_id = _identifier(value.get("vault_id"), "vault_id")
        requested_by = value.get("requested_by")
        if not isinstance(requested_by, str):
            raise ValueError("requested_by must be a string")
        encoded = value.get("payload_to_sign_base64")
        if not isinstance(encoded, str) or len(encoded) > 90_000:
            raise ValueError("payload_to_sign_base64 must be a Base64 string of bounded size")
        try:
            message = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError("invalid payload_to_sign_base64") from exc
        if not 1 <= len(message) <= 65_536:
            raise ValueError("message must contain between 1 and 65536 bytes")
        return cls(request_id, vault_id, requested_by, message)


def parse_pending(value: object) -> list[SignatureRequest]:
    if not isinstance(value, dict):
        raise ValueError("pending response must be an object")
    requests = value.get("requests")
    if not isinstance(requests, list) or len(requests) > 1000:
        raise ValueError("requests must be a list of at most 1000 items")
    parsed = [SignatureRequest.from_json(item) for item in requests]
    if len({item.request_id for item in parsed}) != len(parsed):
        raise ValueError("duplicate request ID in response")
    return parsed
