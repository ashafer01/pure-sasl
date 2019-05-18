from .base import Mechanism


class ExternalMechanism(Mechanism):
    """
    The EXTERNAL mechanism allows a client to request the server to use
    credentials established by means external to the mechanism to
    authenticate the client.
    """
    name = 'EXTERNAL'
    score = 10

    def process_challenge(self, challenge=None):
        self.complete = True
        return b''
