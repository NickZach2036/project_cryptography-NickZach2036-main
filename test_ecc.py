import unittest
import random
from mediator import Mediator
from ecc import ECCParticipant, DummyCurve

class TestECC (unittest.TestCase):
    def test_ecc_encryption (self):
        mediator = Mediator()
        curve = DummyCurve()
        alice = ECCParticipant ("Alice", mediator, curve)
        bob = ECCParticipant ("Bob", mediator, curve)

        random.seed (0)

        message = "Hello"
        alice.start_communication ("Bob", message)

        bob.receive ("Alice", {
            "type": "public_key",
            "public_key": alice.public_key
        })

        alice.receive ("Bob", {
            "type": "public_key_ack",
            "public_key": bob.public_key
        })

        bob.receive ("Alice", {
            "type": "encrypted_message",
            "message": alice.encrypt (message, bob.public_key)
        })

        self.assertEqual (alice.shared_message, bob.shared_message)
        self.assertIsNotNone (alice.shared_message)
        self.assertIsNotNone (bob.shared_message)
        print ("Alice's shared message (ECC):", alice.shared_message)
        print ("Bob's shared message (ECC):", bob.shared_message)

if __name__ == "__main__":
    unittest.main()
