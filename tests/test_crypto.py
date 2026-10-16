import unittest

from group_vault.crypto import (
    SecretSharingError,
    combine_shares,
    split_secret,
)


class TestSecretSharing(unittest.TestCase):
    def test_reconstructs_secret_from_threshold_shares(self) -> None:
        secret = b"week one dummy secret"
        shares = split_secret(secret, t=3, n=5)

        self.assertEqual(combine_shares(shares[:3]), secret)

    def test_rejects_too_few_shares(self) -> None:
        shares = split_secret(b"week one dummy secret", t=3, n=5)

        with self.assertRaises(SecretSharingError):
            combine_shares(shares[:2])

    def test_rejects_threshold_greater_than_total(self) -> None:
        with self.assertRaises(SecretSharingError):
            split_secret(b"week one dummy secret", t=6, n=5)


if __name__ == "__main__":
    unittest.main()
