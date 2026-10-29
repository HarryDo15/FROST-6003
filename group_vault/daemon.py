"""Week 3 polling loop: displays requests without approving or signing them."""

from __future__ import annotations

import hashlib
import math
import sys
import time
from collections import OrderedDict

from group_vault.client import CoordinatorClient, CoordinatorError
from group_vault.types import SignatureRequest


def describe_request(request: SignatureRequest) -> str:
    digest = hashlib.sha256(request.message).hexdigest()
    return (
        f"[request] id={request.request_id!r} vault={request.vault_id!r} "
        f"message_bytes={len(request.message)} sha256={digest}"
    )


def run_daemon(
    coordinator: str,
    node_id: str,
    interval: float = 2.0,
    timeout: float = 5.0,
    once: bool = False,
) -> int:
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("poll interval must be positive and finite")
    if not node_id.strip() or len(node_id) > 128:
        raise ValueError("node ID must have between 1 and 128 characters")
    client = CoordinatorClient(coordinator, timeout)
    seen: OrderedDict[str, SignatureRequest] = OrderedDict()
    print(f"[listen] node={node_id!r}; observation only; Ctrl+C to stop", flush=True)
    failed = False
    try:
        while True:
            try:
                requests = client.pending_requests(node_id)
                if failed:
                    print("[connected] coordinator is reachable again", flush=True)
                failed = False
                for request in requests:
                    previous = seen.get(request.request_id)
                    if previous is None or previous != request:
                        if previous is not None:
                            print(
                                "[warning] request contents changed for an existing ID", flush=True
                            )
                        print(describe_request(request), flush=True)
                        seen[request.request_id] = request
                        seen.move_to_end(request.request_id)
                        if len(seen) > 1000:
                            seen.popitem(last=False)
                if once:
                    print(f"[poll] received {len(requests)} pending request(s)", flush=True)
                    return 0
            except CoordinatorError as exc:
                if not failed or once:
                    print(f"[connection error] {exc}; retrying unless --once", file=sys.stderr)
                failed = True
                if once:
                    return 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[stopped] signer listener stopped", flush=True)
        return 0
