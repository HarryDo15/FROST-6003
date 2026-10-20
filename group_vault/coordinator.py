import sys
import threading
import uuid

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from group_vault.models.api import (
    PendingRequest,
    PendingRequestsResponse,
    ShareSubmission,
    SignatureRequest,
    SignatureResponse,
)

PENDING = "pending"


class RequestStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, PendingRequest] = {}
        self._shares: dict[str, dict[str, str]] = {}

    def create(self, req: SignatureRequest) -> str:
        request_id = f"req_{uuid.uuid4().hex}"
        with self._lock:
            self._requests[request_id] = PendingRequest(request_id=request_id, **req.model_dump())
            self._shares[request_id] = {}
        return request_id

    def pending(self, vault_id: str | None) -> list[PendingRequest]:
        with self._lock:
            return [r for r in self._requests.values() if vault_id in (None, r.vault_id)]

    def add_share(self, sub: ShareSubmission) -> bool:
        with self._lock:
            shares = self._shares.get(sub.request_id)
            if shares is None:
                return False
            shares[sub.node_id] = sub.partial_signature_base64
            return True


app = FastAPI(title="vault-coordinator")
store = RequestStore()


@app.exception_handler(RequestValidationError)
async def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": jsonable_encoder(exc.errors())})


@app.post("/api/v1/sign/request")
def request_signature(req: SignatureRequest) -> SignatureResponse:
    return SignatureResponse(request_id=store.create(req), status=PENDING)


@app.get("/api/v1/sign/pending")
def pending_requests(vault_id: str | None = None) -> PendingRequestsResponse:
    return PendingRequestsResponse(requests=store.pending(vault_id))


@app.post("/api/v1/sign/submit-share")
def submit_share(sub: ShareSubmission) -> SignatureResponse:
    if not store.add_share(sub):
        raise HTTPException(status_code=404, detail="unknown request_id")
    return SignatureResponse(request_id=sub.request_id, status=PENDING)


def main() -> int:
    uvicorn.run(app, host="127.0.0.1", port=8080)
    return 0


if __name__ == "__main__":
    sys.exit(main())
