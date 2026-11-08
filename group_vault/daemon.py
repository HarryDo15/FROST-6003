from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass

from group_vault.client import CoordinatorClient, CoordinatorError
from group_vault.config import NodeConfig
from group_vault.frost import create_commitment, sign_share, validate_commitment
from group_vault.models.api import PendingRequest
from group_vault.prompt import timed_approval
from group_vault.terminal import Status, show_status

MAX_TRACKED_REQUESTS = 1000


@dataclass
class LocalRequest:
    request: PendingRequest
    deadline: float
    approved: bool = False
    rejected: bool = False
    nonce: str | None = None
    commitment: str | None = None
    share: str | None = None
    package_digest: str | None = None
    submitted: bool = False

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline or time.time() >= self.request.expires_at

    def reject(self) -> None:
        self.rejected = True
        self.nonce = None
        self.share = None


def _identity(request: PendingRequest) -> tuple[str, str, str, float]:
    return (
        request.vault_id,
        request.payload_to_sign_base64,
        request.requested_by,
        request.expires_at,
    )


def describe_request(request: PendingRequest) -> str:
    message = base64.b64decode(request.payload_to_sign_base64, validate=True)
    return (
        f"[request] id={request.request_id!r} vault={request.vault_id!r} "
        f"requested_by={request.requested_by!r} message_bytes={len(message)} "
        f"sha256={hashlib.sha256(message).hexdigest()}"
    )


def _process_request(
    entry: LocalRequest,
    request: PendingRequest,
    config: NodeConfig,
    key_package: str,
    client: CoordinatorClient,
    auto_approve: bool,
) -> None:
    if entry.rejected or entry.expired():
        return
    node_id = config.node_id
    if request.status not in ("pending", "signing"):
        raise ValueError("unexpected request status")
    if entry.package_digest is not None and request.status != "signing":
        raise ValueError("request returned to round one after signing")
    if request.status == "signing" and node_id not in request.commitments:
        entry.reject()
        show_status("PENDING", f"Node was not selected for request {request.request_id!r}")
        return
    if not entry.approved:
        if node_id in request.commitments or request.status == "signing":
            raise ValueError("no local nonce exists for the coordinator's commitment")
        message = base64.b64decode(request.payload_to_sign_base64, validate=True)
        print(f"Complete message bytes: {message!r}", flush=True)
        decision = "approved" if auto_approve else timed_approval(entry.deadline)
        if decision != "approved" or entry.expired():
            entry.reject()
            status: Status = "EXPIRED" if decision == "expired" or entry.expired() else "REJECTED"
            show_status(status, f"Request {request.request_id!r} was not approved")
            return
        entry.approved = True
        entry.nonce, entry.commitment = create_commitment(key_package)
    if entry.expired():
        entry.reject()
        return
    if request.status == "pending":
        previous = request.commitments.get(node_id)
        if previous is not None and previous != entry.commitment:
            raise ValueError("coordinator changed this node's commitment")
        if previous is None:
            if entry.commitment is None:
                raise ValueError("local commitment is unavailable")
            response = client.submit_commitment(request.request_id, node_id, entry.commitment)
            if response.status == "expired":
                entry.reject()
                show_status("EXPIRED", f"Request {request.request_id!r} expired")
            elif response.status not in ("pending", "signing"):
                raise ValueError("unexpected commitment response status")
            else:
                show_status("PENDING", f"Commitment accepted for request {request.request_id!r}")
        return
    commitments = request.commitments
    valid_nodes = {str(number) for number in range(1, config.vault.total + 1)}
    if (
        len(commitments) != config.vault.threshold
        or not set(commitments).issubset(valid_nodes)
        or commitments.get(node_id) != entry.commitment
    ):
        raise ValueError("invalid participant set or changed local commitment")
    digest = hashlib.sha256(json.dumps(commitments, sort_keys=True).encode()).hexdigest()
    if entry.package_digest is not None and entry.package_digest != digest:
        raise ValueError("coordinator changed the signing package")
    if entry.share is None:
        for commitment in commitments.values():
            validate_commitment(commitment)
        if entry.nonce is None:
            raise ValueError("signing nonce has already been consumed")
        nonce = entry.nonce
        entry.nonce = None
        entry.package_digest = digest
        message = base64.b64decode(request.payload_to_sign_base64, validate=True)
        entry.share = sign_share(key_package, nonce, message, commitments)
    if entry.expired():
        entry.reject()
        return
    if not entry.submitted:
        response = client.submit_share(request.request_id, node_id, entry.share)
        if response.status == "expired":
            entry.reject()
            show_status("EXPIRED", f"Request {request.request_id!r} expired")
        elif response.status not in ("signing", "completed"):
            raise ValueError("unexpected share response status")
        else:
            entry.submitted = True
            show_status("SUCCESS", f"Signature share accepted for request {request.request_id!r}")


def run_daemon(
    coordinator: str,
    config: NodeConfig,
    key_package: str | None,
    interval: float = 2.0,
    timeout: float = 5.0,
    once: bool = False,
    *,
    interactive: bool = True,
    auto_approve: bool = False,
    allow_http: bool = False,
) -> int:
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("poll interval must be positive and finite")
    if config.node_id not in {str(number) for number in range(1, config.vault.total + 1)}:
        raise ValueError("node ID is not a vault participant")
    client = CoordinatorClient(coordinator, config.token, timeout, allow_http=allow_http)
    seen: dict[str, LocalRequest] = {}
    signing = key_package is not None and (interactive or auto_approve)
    mode = "signing enabled" if signing else "observation only"
    print(f"[listen] node={config.node_id!r}; {mode}; Ctrl+C to stop", flush=True)
    try:
        while True:
            seen = {request_id: entry for request_id, entry in seen.items() if not entry.expired()}
            try:
                requests = client.pending_requests(config.node_id)
            except CoordinatorError as exc:
                show_status("RETRY" if exc.retryable else "REJECTED", str(exc))
                if once or not exc.retryable:
                    return 1
                time.sleep(interval)
                continue
            problem = False
            for request in requests:
                entry = seen.get(request.request_id)
                try:
                    if not math.isfinite(request.expires_at):
                        raise ValueError("invalid request expiry")
                    if entry is not None and _identity(entry.request) != _identity(request):
                        raise ValueError("coordinator changed approved request contents")
                    if request.expires_at <= time.time():
                        continue
                    if entry is None:
                        if len(seen) >= MAX_TRACKED_REQUESTS:
                            show_status(
                                "REJECTED", "Local request capacity reached; listener stopped"
                            )
                            return 1
                        deadline = time.monotonic() + min(300, request.expires_at - time.time())
                        entry = LocalRequest(request.model_copy(deep=True), deadline)
                        seen[request.request_id] = entry
                        print(describe_request(request), flush=True)
                    if request.vault_id != config.vault.vault_id:
                        raise ValueError("coordinator returned a request for a different vault")
                    if signing and key_package is not None:
                        _process_request(entry, request, config, key_package, client, auto_approve)
                except CoordinatorError as exc:
                    problem = True
                    if entry is not None and not exc.retryable:
                        entry.reject()
                    show_status("RETRY" if exc.retryable else "REJECTED", str(exc))
                except (OSError, ValueError) as exc:
                    problem = True
                    if entry is not None:
                        entry.reject()
                    show_status("REJECTED", str(exc))
            if once:
                return 1 if problem else 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[stopped] signer listener stopped", flush=True)
        return 0
