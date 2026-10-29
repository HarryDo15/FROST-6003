import base64
import tempfile
import unittest
from pathlib import Path

from group_vault.storage import EncryptedShareStore


class TestEncryptedShareStore(unittest.TestCase):
    def test_round_trip_encrypts_share_and_rejects_wrong_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = EncryptedShareStore(path)
            share = b"test-only signer share"

            store.store_share("vault-test", "node-1", share, "test-passphrase")

            self.assertEqual(store.load_share("vault-test", "node-1", "test-passphrase"), share)
            self.assertNotIn(
                base64.b64encode(share).decode("ascii"),
                path.read_text(encoding="utf-8"),
            )
            with self.assertRaisesRegex(ValueError, "wrong passphrase"):
                store.load_share("vault-test", "node-1", "incorrect-passphrase")


if __name__ == "__main__":
    unittest.main()
