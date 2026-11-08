import base64
import unittest
from itertools import combinations

from Crypto.Signature import eddsa

from group_vault import frost


class FrostTests(unittest.TestCase):
    def test_any_two_nodes_produce_a_valid_signature(self) -> None:
        vault = frost.generate_keys(threshold=2, total=3)
        message = b"Approve the group transaction"
        public_key = eddsa.import_public_key(base64.b64decode(vault["verifying_key"]))

        for participants in combinations(vault["key_packages"], 2):
            with self.subTest(participants=participants):
                nonces, commitments = {}, {}
                for node in participants:
                    nonces[node], commitments[node] = frost.create_commitment(
                        vault["key_packages"][node]
                    )
                shares = {
                    node: frost.sign_share(
                        vault["key_packages"][node], nonces[node], message, commitments
                    )
                    for node in participants
                }
                signature = frost.aggregate(
                    message, commitments, shares, vault["public_key_package"]
                )
                verifier = eddsa.new(public_key, "rfc8032")
                verifier.verify(message, base64.b64decode(signature))
                with self.assertRaises(ValueError):
                    verifier.verify(b"Changed transaction", base64.b64decode(signature))

    def test_one_node_cannot_sign_for_a_two_node_threshold(self) -> None:
        vault = frost.generate_keys(threshold=2, total=3)
        key = vault["key_packages"]["1"]
        nonces, commitment = frost.create_commitment(key)
        with self.assertRaises(frost.CryptoError):
            frost.sign_share(key, nonces, b"Approve", {"1": commitment})


if __name__ == "__main__":
    unittest.main()
