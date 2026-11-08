# Coordinator polling API

The signer CLI reads Person A's pending-request endpoint. It displays requests and
supports local approval or rejection. Approval does not create a signature or
submit a share to the coordinator.

## Request

```http
GET /api/v1/sign/pending
Accept: application/json
```

The CLI receives all pending requests. Its `--node-id` identifies the local
listener; the coordinator does not authenticate it or check vault membership.
The API supports an optional `vault_id` query filter, but the CLI does not use it.

## Successful response (HTTP 200)

```json
{
  "requests": [
    {
      "request_id": "req_example",
      "vault_id": "demo-vault",
      "payload_to_sign_base64": "ZGVtbyByZXF1ZXN0",
      "requested_by": "demo-user"
    }
  ]
}
```

An empty queue returns `{"requests": []}`. Message bytes use strict Base64. The CLI
computes SHA-256 for display and warns if the contents or requester change for an
existing request ID.

The client accepts request and vault IDs of 1–128 characters, messages of 1–65536
decoded bytes, at most 1000 requests per response, and a response body up to 1 MiB.
These are client limits; the coordinator may accept larger inputs.

## Polling and approval

```sh
vault-cli start --node-id 1 --coordinator http://127.0.0.1:8080 --observe --once
```

Without `--observe`, the CLI prompts for local approval. `--auto-approve` skips
the prompt, but still does not sign or submit anything. In approval mode,
`--once` returns code 1 when a request needs signing because signing is unavailable.

Polling defaults to every 2 seconds with a 5-second HTTP timeout. Invalid
responses and connection failures are reported and retried; `--once` exits with
code 1 on failure. The CLI tracks up to 1000 request IDs in memory and stops when
that limit is reached. Restarting clears this local history.

Local approval expires 300 seconds after the CLI first sees a request. This is
separate from the coordinator's expiry, which begins when the request is created.
Real signing, share submission, and node authentication remain unimplemented in
the signer workflow.
