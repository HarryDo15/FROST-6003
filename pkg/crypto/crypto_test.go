package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestSplitCombine_AnyThresholdSubsetReconstructs(t *testing.T) {
	t.Parallel()

	secret := []byte("correct horse battery staple")
	cases := []struct{ t, n int }{
		{2, 2}, {2, 3}, {3, 5}, {4, 7}, {5, 5},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("t=%d_n=%d", tc.t, tc.n), func(t *testing.T) {
			t.Parallel()

			shares, err := SplitSecret(secret, tc.t, tc.n)
			if err != nil {
				t.Fatalf("SplitSecret: %v", err)
			}
			if len(shares) != tc.n {
				t.Fatalf("got %d shares, want %d", len(shares), tc.n)
			}

			// Every subset of size >= t must reconstruct the secret.
			for size := tc.t; size <= tc.n; size++ {
				for _, idx := range combinations(tc.n, size) {
					got, err := CombineShares(pick(shares, idx))
					if err != nil {
						t.Fatalf("CombineShares(%v): %v", idx, err)
					}
					if !bytes.Equal(got, secret) {
						t.Fatalf("CombineShares(%v) = %q, want %q", idx, got, secret)
					}
				}
			}
		})
	}
}

func TestCombineShares_FewerThanThresholdFails(t *testing.T) {
	t.Parallel()

	const threshold, n = 3, 5
	shares, err := SplitSecret([]byte("top secret"), threshold, n)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	for size := 0; size < threshold; size++ {
		for _, idx := range combinations(n, size) {
			got, err := CombineShares(pick(shares, idx))
			if !errors.Is(err, ErrInsufficientShares) {
				t.Fatalf("CombineShares(%v) error = %v, want %v", idx, err, ErrInsufficientShares)
			}
			if got != nil {
				t.Fatalf("CombineShares(%v) returned data %q alongside error", idx, got)
			}
		}
	}
}

func TestCombineShares_LoweredThresholdHeaderFailsIntegrity(t *testing.T) {
	t.Parallel()

	shares, err := SplitSecret([]byte("top secret"), 3, 5)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	// An attacker rewrites the threshold so two shares pass the count check;
	// the embedded digest must still reject the bogus reconstruction.
	forged := pick(shares, []int{0, 1})
	for _, s := range forged {
		s[1] = 2
	}
	if _, err := CombineShares(forged); !errors.Is(err, ErrIntegrityCheckFailed) {
		t.Fatalf("error = %v, want %v", err, ErrIntegrityCheckFailed)
	}
}

func TestCombineShares_CorruptedShareFailsIntegrity(t *testing.T) {
	t.Parallel()

	shares, err := SplitSecret([]byte("top secret"), 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	subset := pick(shares, []int{0, 2})
	subset[0][headerLen] ^= 0xFF
	if _, err := CombineShares(subset); !errors.Is(err, ErrIntegrityCheckFailed) {
		t.Fatalf("error = %v, want %v", err, ErrIntegrityCheckFailed)
	}
}

func TestCombineShares_RejectsBadInput(t *testing.T) {
	t.Parallel()

	a, err := SplitSecret([]byte("secret A"), 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	b, err := SplitSecret([]byte("a much longer secret B"), 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	c, err := SplitSecret([]byte("secret C"), 3, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	badVersion := bytes.Clone(a[1])
	badVersion[0] = shareVersion + 1

	cases := []struct {
		name   string
		shares [][]byte
		want   error
	}{
		{"nil", nil, ErrInsufficientShares},
		{"too short", [][]byte{a[0], {shareVersion, 2, 0}}, ErrMalformedShare},
		{"unknown version", [][]byte{a[0], badVersion}, ErrMalformedShare},
		{"duplicate", [][]byte{a[0], a[0]}, ErrDuplicateShare},
		{"different lengths", [][]byte{a[0], b[1]}, ErrInconsistentShares},
		{"different thresholds", [][]byte{a[0], c[1]}, ErrInconsistentShares},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := CombineShares(tc.shares); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSplitSecret_RejectsInvalidParameters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		secret []byte
		t, n   int
		want   error
	}{
		{"empty secret", nil, 2, 3, ErrEmptySecret},
		{"threshold below minimum", []byte("s"), 1, 3, ErrInvalidParameters},
		{"threshold above n", []byte("s"), 4, 3, ErrInvalidParameters},
		{"n above maximum", []byte("s"), 2, MaxShares + 1, ErrInvalidParameters},
		{"negative", []byte("s"), -1, -1, ErrInvalidParameters},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			shares, err := SplitSecret(tc.secret, tc.t, tc.n)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if shares != nil {
				t.Fatalf("got %d shares alongside error", len(shares))
			}
		})
	}
}

func TestSplitSecret_DoesNotAliasInput(t *testing.T) {
	t.Parallel()

	secret := []byte("mutable")
	shares, err := SplitSecret(secret, 2, 2)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	secret[0] = 'X'

	got, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if want := []byte("mutable"); !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSplitSecret_MaxShares(t *testing.T) {
	t.Parallel()

	secret := []byte("wide group")
	shares, err := SplitSecret(secret, MaxShares, MaxShares)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}
	got, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

// combinations returns every k-element subset of {0, ..., n-1} as index
// slices in lexicographic order.
func combinations(n, k int) [][]int {
	var out [][]int
	var walk func(start int, cur []int)
	walk = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			walk(i+1, append(cur, i))
		}
	}
	walk(0, make([]int, 0, k))
	return out
}

// pick returns deep copies of shares[i] for each i in idx, so tests may
// mutate the result without affecting other subtests.
func pick(shares [][]byte, idx []int) [][]byte {
	out := make([][]byte, len(idx))
	for i, j := range idx {
		out[i] = bytes.Clone(shares[j])
	}
	return out
}
