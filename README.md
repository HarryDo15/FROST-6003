# Decentralized Group Vault

SE6003 Cryptography project: a vault whose secrets can only be recovered when a
threshold `t` of `n` group members cooperate.

## Layout

| Path               | Purpose                                                         |
| ------------------ | --------------------------------------------------------------- |
| `cmd/coordinator`  | Service that orchestrates share distribution and recovery.      |
| `cmd/vault-cli`    | Member-facing command-line client.                              |
| `pkg/crypto`       | Threshold primitives (Shamir's Secret Sharing).                 |
| `pkg/types`        | Domain types shared by the back end and API consumers.          |

## Development

Requires Go 1.25+ and [golangci-lint v2](https://golangci-lint.run/).

```sh
go test -race ./...   # unit tests
go vet ./...          # static checks
golangci-lint run     # lint (CI requires 0 issues)
```

## `pkg/crypto`

```go
shares, err := crypto.SplitSecret(secret, t, n) // any t of n shares recover secret
secret, err := crypto.CombineShares(shares[:t])
```

Built on HashiCorp's `vault/shamir` (GF(2^8)). Each share carries a small
header (version, threshold) and the split payload includes a SHA-256 digest of
the secret, so supplying fewer than `t` shares, or corrupted or mixed shares,
returns an error instead of a wrong secret. Errors are exported sentinels
(`crypto.ErrInsufficientShares`, `crypto.ErrIntegrityCheckFailed`, …) for use
with `errors.Is`.
