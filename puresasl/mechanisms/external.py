from .base import Mechanism


class ExternalMechanism(Mechanism):
    """
    The EXTERNAL mechanism allows a client to request the server to use
    credentials established by means external to the mechanism to
    authenticate the client.
    Defined in RFC 4422 Appendix A
    """
    name = 'EXTERNAL'
    score = 10

    def __init__(self, sasl, **props):
        Mechanism.__init__(self, sasl)
        self.authzid = None
        self.complete = False

    def process_challenge(self, challenge=None):
        self.complete = True
        return b''

    def process_response(self, response):
        self.authzid = response.decode('utf-8')
        self.complete = True
