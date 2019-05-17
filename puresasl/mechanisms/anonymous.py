from .base import Mechanism


class AnonymousMechanism(Mechanism):
    """
    An anonymous user login mechanism.
    """
    name = 'ANONYMOUS'
    score = 0

    uses_plaintext = False

    def process(self, challenge=None):
        self.complete = True
        return b'Anonymous, None'
