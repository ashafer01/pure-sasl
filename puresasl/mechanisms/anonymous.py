from .base import Mechanism


class AnonymousMechanism(Mechanism):
    """
    An anonymous user login mechanism with both client and server support
    Defined in RFC 4505
    """
    name = 'ANONYMOUS'
    score = 0

    uses_plaintext = False

    def __init__(self, sasl, **props):
        Mechanism.__init__(self, sasl)
        self.message = None

    def process_challenge(self, challenge=None):
        self.complete = True
        return b'Anonymous, None'

    def process_response(self, response):
        self.message = response.decode('utf-8')
        self.complete = True
