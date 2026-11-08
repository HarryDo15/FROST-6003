import argparse
import base64
import hashlib
import hmac
import math
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from group_vault.config import CoordinatorConfig, PublicVault, load_config
from group_vault.frost import aggregate, validate_commitment, validate_vault, verify
from group_vault.logging import logger
from group_vault.models.api import (
    CommitmentSubmission,
    PendingRequest,
    PendingRequestsResponse,
    ShareSubmission,
    SignatureRequest,
    SignatureResponse,
    SignatureResult,
    Status,
)

PENDING: Status = "pending"
SIGNING: Status = "signing"
COMPLETED: Status = "completed"
EXPIRED: Status = "expired"
FAILED: Status = "failed"
PENDING_BATCH_SIZE = 5


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > 100_000:
                response = JSONResponse(
                    status_code=413, content={"detail": "request body too large"}
                )
                await response(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def read_body() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, read_body, send)


class StoreError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class StoredRequest:
    request: SignatureRequest
    deadline: float
    expires_at: float
    status: Status = PENDING
    commitments: dict[str, str] = field(default_factory=dict)
    shares: dict[str, str] = field(default_factory=dict)
    signature_base64: str | None = None
    finished_at: float | None = None


class RequestStore:
    def __init__(
        self,
        config: CoordinatorConfig | PublicVault,
        ttl: float = 300,
        clock: Callable[[], float] = time.monotonic,
        max_requests: int = 1000,
        retention: float = 300,
    ) -> None:
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("TTL must be positive and finite")
        if max_requests < 1 or not math.isfinite(retention) or retention <= 0:
            raise ValueError("request capacity and retention must be positive")
        self.vault = config.vault if isinstance(config, CoordinatorConfig) else config
        validate_vault(
            self.vault.public_key_package,
            self.vault.threshold,
            self.vault.total,
            self.vault.verifying_key,
        )
        self._nodes = {str(index) for index in range(1, self.vault.total + 1)}
        self.ttl = ttl
        self._clock = clock
        self._max_requests = max_requests
        self._retention = retention
        self._lock = threading.Lock()
        self._requests: dict[str, StoredRequest] = {}

    def _finish(self, request_id: str, entry: StoredRequest, status: Status) -> None:
        entry.status = status
        entry.finished_at = self._clock()
        logger.info("request_finished", extra={"request_id": request_id, "status": status})

    def _cleanup(self) -> None:
        now = self._clock()
        remove = []
        for request_id, entry in self._requests.items():
            if entry.status in (PENDING, SIGNING) and now >= entry.deadline:
                self._finish(request_id, entry, EXPIRED)
            if entry.finished_at is not None and now - entry.finished_at >= self._retention:
                remove.append(request_id)
        for request_id in remove:
            del self._requests[request_id]

    def expire(self) -> None:
        with self._lock:
            self._cleanup()

    def _entry(self, request_id: str) -> StoredRequest:
        self._cleanup()
        entry = self._requests.get(request_id)
        if entry is None:
            raise StoreError("unknown request_id", 404)
        return entry

    def _node(self, node_id: str) -> None:
        if node_id not in self._nodes:
            raise StoreError("node does not belong to this vault", 403)

    def create(self, req: SignatureRequest) -> str:
        if req.vault_id != self.vault.vault_id:
            raise StoreError("unknown vault_id", 404)
        with self._lock:
            self._cleanup()
            if len(self._requests) >= self._max_requests:
                raise StoreError("request capacity reached; retry later", 429)
            request_id = f"req_{uuid.uuid4().hex}"
            self._requests[request_id] = StoredRequest(
                request=req.model_copy(deep=True),
                deadline=self._clock() + self.ttl,
                expires_at=time.time() + self.ttl,
            )
            logger.info("request_created", extra={"request_id": request_id, "status": PENDING})
            return request_id

    def pending(self, node_id: str) -> list[PendingRequest]:
        self._node(node_id)
        with self._lock:
            self._cleanup()
            entries = [
                (request_id, entry)
                for request_id, entry in self._requests.items()
                if entry.status == PENDING
                or (entry.status == SIGNING and node_id in entry.commitments)
            ]
            entries.sort(key=lambda item: item[1].status != SIGNING)
            return [
                PendingRequest(
                    **entry.request.model_dump(),
                    request_id=request_id,
                    status=entry.status,
                    expires_at=entry.expires_at,
                    commitments=dict(entry.commitments) if entry.status == SIGNING else {},
                )
                for request_id, entry in entries[:PENDING_BATCH_SIZE]
            ]

    def result(self, request_id: str) -> SignatureResult:
        with self._lock:
            entry = self._entry(request_id)
            return SignatureResult(
                request_id=request_id,
                status=entry.status,
                vault_id=entry.request.vault_id,
                payload_to_sign_base64=entry.request.payload_to_sign_base64,
                signature_base64=entry.signature_base64,
                verified=entry.status == COMPLETED,
            )

    def add_commitment(self, sub: CommitmentSubmission) -> SignatureResponse:
        self._node(sub.node_id)
        with self._lock:
            entry = self._entry(sub.request_id)
            previous = entry.commitments.get(sub.node_id)
            if previous is not None:
                if previous != sub.commitment_base64:
                    raise StoreError("commitment cannot change for this request", 409)
            else:
                if entry.status != PENDING:
                    raise StoreError("request is not accepting commitments", 409)
                validate_commitment(sub.commitment_base64)
                if self._clock() >= entry.deadline:
                    self._finish(sub.request_id, entry, EXPIRED)
                    return SignatureResponse(request_id=sub.request_id, status=entry.status)
                entry.commitments[sub.node_id] = sub.commitment_base64
                if len(entry.commitments) == self.vault.threshold:
                    entry.status = SIGNING
                    logger.info(
                        "participants_selected",
                        extra={"request_id": sub.request_id, "status": SIGNING},
                    )
            return SignatureResponse(request_id=sub.request_id, status=entry.status)

    def add_share(self, sub: ShareSubmission) -> SignatureResponse:
        self._node(sub.node_id)
        with self._lock:
            entry = self._entry(sub.request_id)
            if sub.node_id not in entry.commitments:
                raise StoreError("node is not a selected participant", 403)
            previous = entry.shares.get(sub.node_id)
            if previous is not None:
                if previous != sub.partial_signature_base64:
                    raise StoreError("signature share cannot change for this request", 409)
            else:
                if entry.status != SIGNING:
                    raise StoreError("request is not accepting signature shares", 409)
                entry.shares[sub.node_id] = sub.partial_signature_base64
                if len(entry.shares) == self.vault.threshold:
                    message = base64.b64decode(entry.request.payload_to_sign_base64, validate=True)
                    try:
                        signature = aggregate(
                            message, entry.commitments, entry.shares, self.vault.public_key_package
                        )
                        if not verify(message, signature, self.vault.public_key_package):
                            raise ValueError("aggregated signature did not verify")
                    except ValueError:
                        self._finish(sub.request_id, entry, FAILED)
                    else:
                        if self._clock() >= entry.deadline:
                            self._finish(sub.request_id, entry, EXPIRED)
                        else:
                            entry.signature_base64 = signature
                            self._finish(sub.request_id, entry, COMPLETED)
            return SignatureResponse(request_id=sub.request_id, status=entry.status)


def create_app(config: CoordinatorConfig, request_store: RequestStore | None = None) -> FastAPI:
    store = request_store if request_store is not None else RequestStore(config)
    if store.vault != config.vault:
        raise ValueError("request store vault does not match coordinator config")

    def token_hash(request: Request) -> str:
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token or len(token) > 512:
            raise HTTPException(
                401, "bearer token required", headers={"WWW-Authenticate": "Bearer"}
            )
        return hashlib.sha256(token.encode()).hexdigest()

    def requester(request: Request) -> None:
        if not hmac.compare_digest(token_hash(request), config.requester_token_hash):
            raise HTTPException(401, "invalid requester token")

    def node(request: Request) -> str:
        digest = token_hash(request)
        for node_id, expected in config.node_token_hashes.items():
            if hmac.compare_digest(digest, expected):
                return node_id
        raise HTTPException(401, "invalid node token")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        stop = threading.Event()

        def expire_requests() -> None:
            while not stop.wait(1):
                store.expire()

        worker = threading.Thread(target=expire_requests, daemon=True)
        worker.start()
        logger.info("coordinator_started")
        try:
            yield
        finally:
            stop.set()
            worker.join()
            logger.info("coordinator_stopped")

    app = FastAPI(title="vault-coordinator", lifespan=lifespan)
    app.add_middleware(BodyLimitMiddleware)

    @app.exception_handler(RequestValidationError)
    async def bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=400, content={"detail": errors})

    @app.exception_handler(ValueError)
    async def bad_value(_: Request, exc: ValueError) -> JSONResponse:
        status = exc.status_code if isinstance(exc, StoreError) else 400
        return JSONResponse(status_code=status, content={"detail": str(exc)})

    @app.post("/api/v1/sign/request", dependencies=[Depends(requester)])
    def request_signature(req: SignatureRequest) -> SignatureResponse:
        return SignatureResponse(request_id=store.create(req), status=PENDING)

    @app.get("/api/v1/sign/pending")
    def pending_requests(
        authenticated_node: Annotated[str, Depends(node)],
        node_id: str | None = None,
        vault_id: str | None = None,
    ) -> PendingRequestsResponse:
        if node_id is not None and node_id != authenticated_node:
            raise HTTPException(403, "node_id does not match authenticated node")
        if vault_id is not None and vault_id != config.vault.vault_id:
            raise HTTPException(404, "unknown vault_id")
        return PendingRequestsResponse(requests=store.pending(authenticated_node))

    @app.post("/api/v1/sign/commitment")
    def submit_commitment(
        sub: CommitmentSubmission, authenticated_node: Annotated[str, Depends(node)]
    ) -> SignatureResponse:
        if sub.node_id != authenticated_node:
            raise HTTPException(403, "node_id does not match authenticated node")
        return store.add_commitment(sub)

    @app.post("/api/v1/sign/submit-share")
    def submit_share(
        sub: ShareSubmission, authenticated_node: Annotated[str, Depends(node)]
    ) -> SignatureResponse:
        if sub.node_id != authenticated_node:
            raise HTTPException(403, "node_id does not match authenticated node")
        return store.add_share(sub)

    @app.get("/api/v1/sign/result", dependencies=[Depends(requester)])
    def signature_result(request_id: str) -> SignatureResult:
        return store.result(request_id)

    return app


def main() -> int:
    parser = argparse.ArgumentParser(prog="vault-coordinator")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    try:
        config = load_config(args.config, CoordinatorConfig)
        uvicorn.run(create_app(config), host=args.host, port=args.port)
    except (OSError, ValueError):
        print("vault-coordinator: invalid configuration or startup failure", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
