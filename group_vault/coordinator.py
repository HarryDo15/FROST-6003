import base64
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from group_vault.crypto import MAX_SHARES, MIN_THRESHOLD, combine_shares, validate_shares
from group_vault.logging import logger
from group_vault.models.api import (
    PendingRequest,
    PendingRequestsResponse,
    ShareSubmission,
    SignatureRequest,
    SignatureResponse,
    SignatureResult,
)

PENDING = "pending"
COMPLETED = "completed"
EXPIRED = "expired"


@dataclass
class StoredRequest:
    request: PendingRequest
    deadline: float
    shares: dict[str, bytes] = field(default_factory=dict)
    status: str = PENDING
    signature_base64: str | None = None


class RequestStore:
    def __init__(
        self,
        threshold: int = 2,
        ttl: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not MIN_THRESHOLD <= threshold <= MAX_SHARES or ttl <= 0:
            raise ValueError("invalid threshold or TTL")
        self.threshold = threshold
        self.ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._requests: dict[str, StoredRequest] = {}

    def _expire(self, entry: StoredRequest) -> None:
        if entry.status == PENDING and self._clock() >= entry.deadline:
            entry.status = EXPIRED
            entry.shares.clear()
            logger.info(
                "request_expired",
                extra={"request_id": entry.request.request_id, "status": EXPIRED},
            )

    def expire(self) -> None:
        with self._lock:
            for entry in self._requests.values():
                self._expire(entry)

    def create(self, req: SignatureRequest) -> str:
        request_id = f"req_{uuid.uuid4().hex}"
        with self._lock:
            self._requests[request_id] = StoredRequest(
                request=PendingRequest(request_id=request_id, **req.model_dump()),
                deadline=self._clock() + self.ttl,
            )
            logger.info("request_created", extra={"request_id": request_id, "status": PENDING})
        return request_id

    def pending(self, vault_id: str | None) -> list[PendingRequest]:
        with self._lock:
            result = []
            for entry in self._requests.values():
                self._expire(entry)
                if entry.status == PENDING and vault_id in (None, entry.request.vault_id):
                    result.append(entry.request.model_copy())
            return result

    def result(self, request_id: str) -> SignatureResult:
        with self._lock:
            entry = self._requests[request_id]
            self._expire(entry)
            return SignatureResult(
                request_id=request_id,
                status=entry.status,
                signature_base64=entry.signature_base64,
            )

    def add_share(self, sub: ShareSubmission) -> SignatureResponse:
        with self._lock:
            entry = self._requests[sub.request_id]
            self._expire(entry)
            context = {"request_id": sub.request_id, "node_id": sub.node_id}
            if entry.status == PENDING and sub.node_id not in entry.shares:
                share = base64.b64decode(sub.partial_signature_base64, validate=True)
                candidates = [*entry.shares.values(), share]
                validate_shares(candidates)
                if share[1] != self.threshold:
                    raise ValueError("share threshold does not match coordinator threshold")
                if len(candidates) == self.threshold:
                    signature = combine_shares(candidates)
                    entry.signature_base64 = base64.b64encode(signature).decode("ascii")
                    entry.status = COMPLETED
                    entry.shares.clear()
                    logger.info("request_completed", extra={**context, "status": COMPLETED})
                else:
                    entry.shares[sub.node_id] = share
                    logger.info("share_accepted", extra={**context, "status": PENDING})
            return SignatureResponse(request_id=sub.request_id, status=entry.status)


def create_app(request_store: RequestStore | None = None) -> FastAPI:
    store = request_store if request_store is not None else RequestStore()

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

    @app.exception_handler(RequestValidationError)
    async def bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=400, content={"detail": errors})

    @app.post("/api/v1/sign/request")
    def request_signature(req: SignatureRequest) -> SignatureResponse:
        return SignatureResponse(request_id=store.create(req), status=PENDING)

    @app.get("/api/v1/sign/pending")
    def pending_requests(vault_id: str | None = None) -> PendingRequestsResponse:
        return PendingRequestsResponse(requests=store.pending(vault_id))

    @app.post("/api/v1/sign/submit-share")
    def submit_share(sub: ShareSubmission) -> SignatureResponse:
        try:
            return store.add_share(sub)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown request_id") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/sign/result")
    def signature_result(request_id: str) -> SignatureResult:
        try:
            return store.result(request_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown request_id") from exc

    return app


app = create_app()


def main() -> int:
    uvicorn.run(app, host="127.0.0.1", port=8080)
    return 0


if __name__ == "__main__":
    sys.exit(main())
