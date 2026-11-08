"""HTTP polling client for the coordinator API."""

from __future__ import annotations

import json
import math
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from group_vault.types import SignatureRequest, parse_pending


class CoordinatorError(RuntimeError):
    """A coordinator request failed or returned an invalid response."""


class CoordinatorClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        parts = urlsplit(base_url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError("coordinator must be an HTTP(S) URL without credentials or query")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def pending_requests(self, node_id: str) -> list[SignatureRequest]:
        if not node_id.strip() or len(node_id) > 128:
            raise ValueError("node ID must have between 1 and 128 characters")
        request = Request(
            f"{self.base_url}/api/v1/sign/pending",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise CoordinatorError(f"unexpected HTTP status {response.status}")
                body = response.read(1_048_577)
            if len(body) > 1_048_576:
                raise CoordinatorError("coordinator response exceeds 1 MiB")
            return parse_pending(json.loads(body))
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise CoordinatorError(f"coordinator returned HTTP {status}") from exc
        except (OSError, HTTPException) as exc:
            raise CoordinatorError("cannot reach coordinator or request timed out") from exc
        except ValueError as exc:
            raise CoordinatorError("invalid coordinator response") from exc
