# Proposed Week 3 polling API — demo-v1

Status: PROPOSAL, pending agreement with Person A. This describes request
observation only. It does not define a complete FROST signing API.

## Request

GET /requests/pending?node_id=1
Accept: application/json

node_id is a string. It identifies a desired queue; it is not authentication.
The live backend must authenticate the node before authorizing queue access.

## Successful response (HTTP 200)

```json
{
  "api_version": "demo-v1",
  "requests": [
    {
      "request_id": "demo-request-001",
      "vault_id": "week2-demo",
      "node_ids": ["1", "2", "3", "4", "5"],
      "message_b64": "V2VlayAzIG1vY2sgcmVxdWVzdA=="
    }
  ]
}
```

No work: use the same envelope with `requests: []`.
Binary message bytes use strict Base64, not a precomputed hash. The CLI computes
SHA-256 for display only. It does not prescribe the FROST message hashing rules.
Request IDs must identify immutable request contents. The client warns if an ID's
contents change during its current run. node_ids lists nodes invited to observe
the request; it is not the finalized FROST participant/commitment set.

Limits: identifiers 1–128 characters; at most 255 unique node IDs per request;
messages at most 65536 decoded bytes; at most 1000 requests per response; total
response body at most 1 MiB. A node-specific queue response must include only
requests containing that node in node_ids.

## Errors and polling

Non-200 responses, invalid JSON/schema, connection errors and timeouts are errors.
Continuous mode retries after the configured interval; --once exits with code 1.
The request timeout defaults to 5 seconds. Poll interval defaults to 2 seconds.
The client suppresses unchanged requests using a bounded, in-memory cache of 1000
IDs. Restarting the listener clears it. This is display deduplication, not replay
protection, delivery acknowledgement, signing authorization, or nonce tracking.

## Mock behavior

`python -m group_vault.mock_coordinator` binds only to 127.0.0.1:8000. Nodes 1–5
receive the same static demo request on every poll; other IDs receive an empty
queue. The server is intentionally unauthenticated and uses dummy data.

## Still required before Week 4

Agree on the real FROST library/ciphersuite, public key metadata, authentication,
request expiration/cancellation, exact message encoding, commitment submission,
participant selection, signing-package delivery, signature-share submission and
final result/status. Private key shares and secret nonces stay on signer nodes.
