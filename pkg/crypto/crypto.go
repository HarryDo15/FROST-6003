// Package crypto provides the threshold secret-sharing primitives used by the
// group vault.
//
// It wraps HashiCorp's audited Shamir's Secret Sharing implementation
// (github.com/hashicorp/vault/shamir, arithmetic over GF(2^8)) and adds a
// small envelope around each share so that reconstruction fails loudly
// instead of silently returning garbage:
//
//	share = version (1 byte) || threshold (1 byte) || shamir part
//
// The Shamir part encodes secret || SHA-256(secret). On combine, the
// threshold header gives a clear error when too few shares are supplied, and
// the embedded digest detects corrupted, mixed or forged shares (including a
// share whose threshold header was lowered).
//
// Shares reveal the length of the secret but nothing about its contents when
// fewer than the threshold are known.
package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/shamir"
)

const (
	// MinThreshold is the smallest supported threshold t.
	MinThreshold = 2
	// MaxShares is the largest supported number of shares n. It is bounded by
	// the size of the GF(2^8) field used by the underlying scheme.
	MaxShares = 255

	shareVersion byte = 1
	headerLen         = 2 // version + threshold
	digestLen         = sha256.Size
	xCoordLen         = 1 // appended to every part by the shamir package
	minShareLen       = headerLen + 1 + digestLen + xCoordLen
)

// Errors returned by SplitSecret and CombineShares. Callers should compare
// against them with errors.Is.
var (
	ErrEmptySecret          = errors.New("crypto: secret must not be empty")
	ErrInvalidParameters    = errors.New("crypto: invalid threshold parameters")
	ErrInsufficientShares   = errors.New("crypto: not enough shares to reconstruct secret")
	ErrMalformedShare       = errors.New("crypto: malformed share")
	ErrInconsistentShares   = errors.New("crypto: shares do not belong to the same split")
	ErrDuplicateShare       = errors.New("crypto: duplicate share")
	ErrIntegrityCheckFailed = errors.New("crypto: reconstructed secret failed integrity check")
)

// SplitSecret splits secret into n shares such that any t of them reconstruct
// it and any t-1 or fewer reveal nothing about it. It requires
// MinThreshold <= t <= n <= MaxShares.
func SplitSecret(secret []byte, t, n int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if t < MinThreshold || t > MaxShares || n < t || n > MaxShares {
		return nil, fmt.Errorf("%w: need %d <= t <= n <= %d, got t=%d n=%d",
			ErrInvalidParameters, MinThreshold, MaxShares, t, n)
	}

	digest := sha256.Sum256(secret)
	payload := make([]byte, 0, len(secret)+digestLen)
	payload = append(payload, secret...)
	payload = append(payload, digest[:]...)

	parts, err := shamir.Split(payload, n, t)
	if err != nil {
		return nil, fmt.Errorf("crypto: split secret: %w", err)
	}

	shares := make([][]byte, len(parts))
	for i, part := range parts {
		share := make([]byte, 0, headerLen+len(part))
		share = append(share, shareVersion, byte(t))
		share = append(share, part...)
		shares[i] = share
	}
	return shares, nil
}

// CombineShares reconstructs the secret from shares produced by SplitSecret.
// At least t distinct shares from the same split are required; the order of
// shares does not matter and extra shares beyond t are accepted.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("%w: no shares provided", ErrInsufficientShares)
	}

	var threshold, shareLen int
	parts := make([][]byte, len(shares))
	seen := make(map[byte]struct{}, len(shares))
	for i, share := range shares {
		t, l, err := parseHeader(share)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i, err)
		}
		if i == 0 {
			threshold, shareLen = t, l
		} else if t != threshold || l != shareLen {
			return nil, fmt.Errorf("share %d: %w", i, ErrInconsistentShares)
		}

		x := share[len(share)-1]
		if _, dup := seen[x]; dup {
			return nil, fmt.Errorf("share %d: %w", i, ErrDuplicateShare)
		}
		seen[x] = struct{}{}

		parts[i] = share[headerLen:]
	}

	if len(shares) < threshold {
		return nil, fmt.Errorf("%w: have %d, need %d",
			ErrInsufficientShares, len(shares), threshold)
	}

	payload, err := shamir.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("crypto: combine shares: %w", err)
	}

	secretLen := len(payload) - digestLen
	secret, digest := payload[:secretLen], payload[secretLen:]
	want := sha256.Sum256(secret)
	if subtle.ConstantTimeCompare(digest, want[:]) != 1 {
		return nil, ErrIntegrityCheckFailed
	}
	return secret, nil
}

// parseHeader validates a share's envelope and returns its threshold and
// total length.
func parseHeader(share []byte) (threshold, length int, err error) {
	if len(share) < minShareLen {
		return 0, 0, fmt.Errorf("%w: length %d is below minimum %d",
			ErrMalformedShare, len(share), minShareLen)
	}
	if share[0] != shareVersion {
		return 0, 0, fmt.Errorf("%w: unsupported version %d", ErrMalformedShare, share[0])
	}
	threshold = int(share[1])
	if threshold < MinThreshold {
		return 0, 0, fmt.Errorf("%w: threshold %d is below minimum %d",
			ErrMalformedShare, threshold, MinThreshold)
	}
	return threshold, len(share), nil
}
