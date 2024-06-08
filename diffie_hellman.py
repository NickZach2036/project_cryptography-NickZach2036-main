import random

class DiffieHellmanParticipant:
    def __init__(self, name, mediator):
        self.name = name
        self.mediator = mediator
        self.p = None
        self.g = None
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.mediator.register (self)

    def generate_private_key (self):
        self.private_key = random.randint (2, 100)

    def calculate_public_key (self):
        self.public_key = pow (self.g, self.private_key, self.p)

    def calculate_shared_key (self, other_public_key):
        self.shared_key = pow (other_public_key, self.private_key, self.p)

    def receive (self, from_participant, message):
        if message ["type"] == "public_parameters":
            self.p = message ["p"]
            self.g = message ["g"]
            self.generate_private_key()
            self.calculate_public_key()

            self.mediator.send (self.name, from_participant, {
                "type": "public_key",
                "public_key": self.public_key
            })
        elif message ["type"] == "public_key": self.calculate_shared_key (message ["public_key"])

    def start_communication (self, p, g, other_participant):
        self.p = p
        self.g = g
        self.generate_private_key()
        self.calculate_public_key()

        self.mediator.send (self.name, other_participant, {
            "type": "public_parameters",
            "p": self.p,
            "g": self.g
        })

        self.mediator.send (self.name, other_participant, {
            "type": "public_key",
            "public_key": self.public_key
        }