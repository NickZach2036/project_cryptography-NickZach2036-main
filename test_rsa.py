import unittest
import random
from mediator import Mediator
from rsa import RSAParticipant

class TestRSA (unittest.TestCase):
    def test_rsa_encryption (self):
        mediator = Mediator()
        alice = RSAParticipant ("Alice", mediator)
        bob = RSAParticipant ("Bob", mediator)

        random.seed (0)

        message = 42
        alice.start_communication ("Bob", message)

        bob.start_communication ("Alice", message)

        self.assertEqual (alice.shared_message, bob.shared_message)
        self.assertIsNotNone (alice.shared_message)
        self.assertIsNotNone (bob.shared_message)
        print ("Alice's shared message (RSA):", alice.shared_message)
        print ("Bob's shared message (RSA):", bob.shared_message)

if __name__ == "__main__":
    unittest.main(
