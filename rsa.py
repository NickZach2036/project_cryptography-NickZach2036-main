class RSAParticipant:
    def __init__(self, name, mediator):
        self.name = name
        self.mediator = mediator
        self.n = None
        self.e = None
        self.d = None
        self.public_key = None
        self.private_key = None
        self.supported_standards = ["RSA"]
        self.mediator.register (self)

    def generate_keys (self):
        p = 61
        q = 53
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.e = 17
        self.d = pow (self.e, -1, phi)
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)
        print (f"{self.name} generated keys: public_key={self.public_key}, private_key={self.private_key}")

    def encrypt (self, message, public_key):
        n, e = public_key
        encrypted_message = pow (message, e, n)
        print (f"{self.name} encrypted message: {message} to {encrypted_message} using public_key={public_key}")

        return encrypted_message

    def decrypt (self, ciphertext):
        n, d = self.private_key
        decrypted_message = pow (ciphertext, d, n)
        print (f"{self.name} decrypted message: {ciphertext} to {decrypted_message} using private_key={self.private_key}")
        
        return decrypted_message

    def receive (self, from_participant, message):
        print (f"{self.name} received message from {from_participant}: {message}")

        if message ["type"] == "public_key":
            self.other_public_key = message ["public_key"]
            print (f"{self.name} received public key: {self.other_public_key}")

            if self.private_key is None: self.generate_keys()

            encrypted_message = self.encrypt (message["message"], self.other_public_key)
            self.shared_message = self.decrypt (encrypted_message)
            print (f"{self.name} decrypted shared message: {self.shared_message}")

    def start_communication (self, other_participant, message):
        if not self.mediator.check_standard(self, "RSA"):
            print (f"{self.name} does not support RSA.")

            return
        
        self.generate_keys()
        print (f"{self.name} starting communication with {other_participant}")
        
        self.mediator.send (self.name, other_participant, {
            "type": "public_key",
            "public_key": self.public_key,
            "message": message
        })
