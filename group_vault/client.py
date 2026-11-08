from __future__ import annotations

import base64
import ipaddress
import json
import math
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from group_vault.models.api import (
    PendingRequest,
    PendingRequestsResponse,
    SignatureResponse,
    SignatureResult,
)


class CoordinatorError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


class CoordinatorClient:
    def __init__(
        self, base_url: str, token: str, timeout: float = 5.0, *, allow_http: bool = False
    ) -> None:
        parts = urlsplit(base_url)
        _ = parts.port
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError("coordinator must be an HTTP(S) URL without credentials or query")
        try:
            loopback = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            loopback = parts.hostname.lower() == "localhost"
        if parts.scheme == "http" and not loopback and not allow_http:
            raise ValueError(
                "use HTTPS outside localhost, or explicitly allow HTTP on a trusted network"
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if not token or any(char.isspace() for char in token):
            raise ValueError("coordinator token must be nonempty and contain no whitespace")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = build_opener(NoRedirect())

    def _request(self, path: str, body: dict[str, str] | None = None) -> bytes:
        request = Request(
            f"{self.base_url}{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                contents: bytes = response.read(1_048_577)
            if len(contents) > 1_048_576:
                raise CoordinatorError("coordinator response exceeds 1 MiB")
            return contents
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise CoordinatorError(
                f"coordinator returned HTTP {status}",
                retryable=status in (408, 429) or status >= 500,
            ) from exc
        except (OSError, HTTPException) as exc:
            raise CoordinatorError(
                "coordinator unavailable or request timed out", retryable=True
            ) from exc

    def pending_requests(self, node_id: str) -> list[PendingRequest]:
        contents = self._request(f"/api/v1/sign/pending?{urlencode({'node_id': node_id})}")
        try:
            pending = PendingRequestsResponse.model_validate_json(contents)
            if len(pending.requests) > 1000:
                raise ValueError("too many requests")
            if len({request.request_id for request in pending.requests}) != len(pending.requests):
                raise ValueError("duplicate request ID")
            return pending.requests
        except ValueError as exc:
            raise CoordinatorError("invalid pending response") from exc

    def _submit(self, path: str, body: dict[str, str]) -> SignatureResponse:
        contents = self._request(path, body)
        try:
            result = SignatureResponse.model_validate_json(contents)
            if result.request_id != body["request_id"]:
                raise ValueError("request ID mismatch")
            return result
        except ValueError as exc:
            raise CoordinatorError("invalid submission response") from exc

    def submit_commitment(
        self, request_id: str, node_id: str, commitment: str
    ) -> SignatureResponse:
        return self._submit(
            "/api/v1/sign/commitment",
            {"request_id": request_id, "node_id": node_id, "commitment_base64": commitment},
        )

    def submit_share(self, request_id: str, node_id: str, share: str) -> SignatureResponse:
        return self._submit(
            "/api/v1/sign/submit-share",
            {"request_id": request_id, "node_id": node_id, "partial_signature_base64": share},
        )

    def create_request(self, vault_id: str, message: bytes, requested_by: str) -> SignatureResponse:
        contents = self._request(
            "/api/v1/sign/request",
            {
                "vault_id": vault_id,
                "payload_to_sign_base64": base64.b64encode(message).decode("ascii"),
                "requested_by": requested_by,
            },
        )
        try:
            return SignatureResponse.model_validate_json(contents)
        except ValueError as exc:
            raise CoordinatorError("invalid request response") from exc

    def result(self, request_id: str) -> SignatureResult:
        contents = self._request(f"/api/v1/sign/result?{urlencode({'request_id': request_id})}")
        try:
            result = SignatureResult.model_validate_json(contents)
            if result.request_id != request_id:
                raise ValueError("request ID mismatch")
            return result
        except ValueError as exc:
            raise CoordinatorError("invalid result response") from exc
