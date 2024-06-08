class Mediator:
    def __init__(self):
        self.participants = {}

    def register (self, participant):
        self.participants [participant.name] = participant

    def send (self, from_participant, to_participant, message):
        if to_participant in self.participants: self.participants [to_participant].receive (from_participant, message)

    def check_standard (self, participant, standard):
        if standard not in participant.supported_standards: return False
        
        return Tru