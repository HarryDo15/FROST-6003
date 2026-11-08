"""Polling, local request deadlines, and optional operator authorization."""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Literal

from group_vault.client import CoordinatorClient, CoordinatorError
from group_vault.prompt import Decision, timed_approval
from group_vault.terminal import show_status
from group_vault.types import SignatureRequest

REQUEST_TTL = 300.0
MAX_TRACKED_REQUESTS = 1000
State = Literal["pending", "approved", "rejected", "expired"]


@dataclass
class LocalRequest:
    request: SignatureRequest
    deadline: float
    state: State = "pending"


def describe_request(request: SignatureRequest) -> str:
    digest = hashlib.sha256(request.message).hexdigest()
    return (
        f"[request] id={request.request_id!r} vault={request.vault_id!r} "
        f"message_bytes={len(request.message)} sha256={digest}"
    )


def authorize(entry: LocalRequest, auto_approve: bool, now: float | None = None) -> Decision:
    current = time.monotonic() if now is None else now
    if current >= entry.deadline:
        entry.state = "expired"
    elif auto_approve:
        entry.state = "approved"
    else:
        entry.state = timed_approval(entry.deadline)
    # Never accept a response that arrives after its deadline.
    if time.monotonic() >= entry.deadline:
        entry.state = "expired"
    if entry.state == "expired":
        show_status("EXPIRED", f"Request {ascii(entry.request.request_id)} exceeded 300 seconds")
        return "expired"
    if entry.state == "rejected":
        show_status("REJECTED", f"Request {ascii(entry.request.request_id)} declined locally")
        return "rejected"
    show_status("PENDING", "Approved locally; FROST signing is unavailable. Nothing submitted.")
    return "approved"


def run_daemon(
    coordinator: str,
    node_id: str,
    interval: float = 2.0,
    timeout: float = 5.0,
    once: bool = False,
    *,
    interactive: bool = False,
    auto_approve: bool = False,
) -> int:
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("poll interval must be positive and finite")
    if not node_id.strip() or len(node_id) > 128:
        raise ValueError("node ID must have between 1 and 128 characters")
    client = CoordinatorClient(coordinator, timeout)
    seen: OrderedDict[str, LocalRequest] = OrderedDict()
    mode = "authorization enabled" if interactive or auto_approve else "observation only"
    print(f"[listen] node={node_id!r}; {mode}; Ctrl+C to stop", flush=True)
    failed = False
    try:
        while True:
            try:
                requests = client.pending_requests(node_id)
                if failed:
                    print("[connected] coordinator is reachable again", flush=True)
                show_status("SYNCED", f"Received {len(requests)} pending request(s)")
                failed = False
                received_at = time.monotonic()
                new_entries = []
                problem = False
                # Assign deadlines to the entire batch before displaying any prompt.
                for request in requests:
                    previous = seen.get(request.request_id)
                    if previous is not None:
                        if previous.request != request:
                            previous.state = "rejected"
                            show_status("REJECTED", "Request contents changed for an existing ID")
                            problem = True
                        continue
                    if len(seen) >= MAX_TRACKED_REQUESTS:
                        show_status(
                            "REJECTED", "Local lifecycle capacity reached; listener stopped"
                        )
                        return 1
                    entry = LocalRequest(request, received_at + REQUEST_TTL)
                    seen[request.request_id] = entry
                    new_entries.append(entry)
                for entry in seen.values():
                    if (
                        entry.state in ("pending", "approved")
                        and time.monotonic() >= entry.deadline
                    ):
                        entry.state = "expired"
                        show_status("EXPIRED", f"Request {ascii(entry.request.request_id)} expired")
                for entry in new_entries:
                    print(describe_request(entry.request), flush=True)
                    if entry.state == "expired":
                        problem = True
                        continue
                    show_status("PENDING", f"Awaiting authorization; TTL {REQUEST_TTL:.0f} seconds")
                    if interactive or auto_approve:
                        print(f"Complete message bytes: {entry.request.message!r}", flush=True)
                        authorize(entry, auto_approve)
                        # Without the real signing adapter, even approval is not signature success.
                        problem = True
                if once:
                    print(f"[poll] received {len(requests)} pending request(s)", flush=True)
                    return 1 if problem else 0
            except CoordinatorError as exc:
                show_status("REJECTED", f"API request failed: {exc}")
                failed = True
                if once:
                    return 1
                show_status("RETRY", f"Retrying in {interval:g} seconds")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[stopped] signer listener stopped", flush=True)
        return 0
    except (OSError, ValueError) as exc:
        show_status("REJECTED", f"Listener failed: {exc}")
        return 1
