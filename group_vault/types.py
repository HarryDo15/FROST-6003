"""Proposed Week 3 polling types; agree this contract with Person A."""

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
    node_ids: tuple[str, ...]
    message: bytes

    @classmethod
    def from_json(cls, value: object) -> SignatureRequest:
        if not isinstance(value, dict):
            raise ValueError("request must be an object")
        request_id = _identifier(value.get("request_id"), "request_id")
        vault_id = _identifier(value.get("vault_id"), "vault_id")
        node_ids = value.get("node_ids")
        if not isinstance(node_ids, list) or not 1 <= len(node_ids) <= 255:
            raise ValueError("node_ids must contain between 1 and 255 identifiers")
        nodes = tuple(_identifier(node, "node_id") for node in node_ids)
        if len(set(nodes)) != len(nodes):
            raise ValueError("duplicate node identifier")
        encoded = value.get("message_b64")
        if not isinstance(encoded, str) or len(encoded) > 90_000:
            raise ValueError("message_b64 must be a Base64 string of bounded size")
        try:
            message = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError("invalid message_b64") from exc
        if len(message) > 65_536:
            raise ValueError("message exceeds 65536 bytes")
        return cls(request_id, vault_id, nodes, message)


def parse_pending(value: object) -> list[SignatureRequest]:
    if not isinstance(value, dict) or value.get("api_version") != "demo-v1":
        raise ValueError("unsupported or missing api_version")
    requests = value.get("requests")
    if not isinstance(requests, list) or len(requests) > 1000:
        raise ValueError("requests must be a list of at most 1000 items")
    parsed = [SignatureRequest.from_json(item) for item in requests]
    if len({item.request_id for item in parsed}) != len(parsed):
        raise ValueError("duplicate request ID in response")
    return parsed
