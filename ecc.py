import random

class EllipticCurve:
    def __init__(self, p, a, b, g, n):
        self.p = p
        self.a = a
        self.b = b
        self.g = g
        self.n = n

    def add (self, point1, point2):
        if point1 == (None, None): return point2

        if point2 == (None, None): return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 == -y2 % self.p: return (None, None)

        if x1 == x2: m = (3 * x1 * x1 + self.a) * pow (2 * y1, -1, self.p)
        else: m = (y2 - y1) * pow (x2 - x1, -1, self.p)

        m %= self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def multiply (self, point, scalar):
        result = (None, None)
        addend = point

        while scalar:
            if scalar & 1: result = self.add(result, addend)

            addend = self.add (addend, addend)
            scalar >>= 1

        return result

class ECCParticipant:
    def __init__(self, name, mediator, curve):
        self.name = name
        self.mediator = mediator
        self.curve = curve
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.supported_standards = ["ECC"]
        self.other_public_key = None
        self.mediator.register (self)

    def generate_keys (self):
        self.private_key = random.randint (1, self.curve.n - 1)
        self.public_key = self.curve.multiply (self.curve.g, self.private_key)
        print (f"{self.name} generated keys: public_key={self.public_key}, private_key={self.private_key}")

    def encrypt (self, message, public_key):
        k = random.randint (1, self.curve.n - 1)
        R = self.curve.multiply (self.curve.g, k)
        S = self.curve.multiply (public_key, k)

        if S == (None, None): raise ValueError ("Elliptic curve point multiplication resulted in None")

        encrypted_message = self.xor (message.encode(), S [0].to_bytes (32, byteorder='big'))
        print (f"{self.name} encrypted message: {message} to {encrypted_message} using public_key={public_key}")
        
        return (R, encrypted_message)

    def decrypt (self, ciphertext):
        R, encrypted_message = ciphertext
        S = self.curve.multiply (R, self.private_key)
        if S == (None, None): raise ValueError ("Elliptic curve point multiplication resulted in None")

        decrypted_message = self.xor (encrypted_message, S [0].to_bytes (32, byteorder='big')).decode()
        print (f"{self.name} decrypted message: {encrypted_message} to {decrypted_message} using private_key={self.private_key}")
        
        return decrypted_message

    def xor (self, data, key):
        return bytes (a ^ b for a, b in zip (data, key))

    def receive (self, from_participant, message):
        print (f"{self.name} received message from {from_participant}: {message}")

        if message ["type"] == "public_key":
            self.other_public_key = message ["public_key"]
            print (f"{self.name} received public key: {self.other_public_key}")
            self.generate_keys()

            self.mediator.send (self.name, from_participant, {
                "type": "public_key_ack",
                "public_key": self.public_key
            })
        elif message ["type"] == "public_key_ack":
            self.other_public_key = message ["public_key"]
            print (f"{self.name} received public key ack: {self.other_public_key}")
            encrypted_message = self.encrypt (self.shared_message, self.other_public_key)

            self.mediator.send (self.name, from_participant, {
                "type": "encrypted_message",
                "message": encrypted_message
            })
        elif message ["type"] == "encrypted_message":
            self.shared_message = self.decrypt (message["message"])
            print (f"{self.name} decrypted shared message: {self.shared_message}")

    def start_communication (self, other_participant, message):
        if not self.mediator.check_standard(self, "ECC"):
            print (f"{self.name} does not support ECC.")

            return
        
        self.generate_keys()
        self.shared_message = message
        print (f"{self.name} starting communication with {other_participant}")
        self.mediator.send (self.name, other_participant, {
            "type": "public_key",
            "public_key": self.public_key
        })

class DummyCurve:
    def __init__ (self):
        self.p = 233
        self.a = 2
        self.b = 3
        self.g = (2, 3)
        self.n = 17

    def add (self, point1, point2):
        if point1 == (None, None): return point2

        if point2 == (None, None): return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 == -y2 % self.p: return (None, None)

        if x1 == x2: m = (3 * x1 * x1 + self.a) * pow (2 * y1, -1, self.p)
        else: m = (y2 - y1) * pow (x2 - x1, -1, self.p)

        m %= self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def multiply (self, point, scalar):
        result = (None, None)
        addend = point

        while scalar:
            if scalar & 1: result = self.add (result, addend)

            addend = self.add (addend, addend)
            scalar >>= 1

        return result
