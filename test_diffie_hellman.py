import unittest
import random
from mediator import Mediator
from diffie_hellman import DiffieHellmanParticipant

class TestDiffieHellman (unittest.TestCase):
    def test_diffie_hellman_key_exchange (self):
        mediator = Mediator()
        alice = DiffieHellmanParticipant ("Alice", mediator)
        bob = DiffieHellmanParticipant ("Bob", mediator)

        random.seed (0)

        alice.start_communication (p = 23, g = 5, other_participant="Bob")

        self.assertEqual (alice.shared_key, bob.shared_key)
        self.assertIsNotNone (alice.shared_key)
        self.assertIsNotNone (bob.shared_key)
        print ("Alice's shared key:", alice.shared_key)
        print ("Bob's shared key:", bob.shared_key)

if __name__ == "__main__":
    unittest.main()