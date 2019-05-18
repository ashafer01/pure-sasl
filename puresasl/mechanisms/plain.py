from .base import Mechanism, _b


class PlainMechanism(Mechanism):
    """
    A plaintext user/password based mechanism.
    """
    name = 'PLAIN'
    score = 1

    allows_anonymous = False

    def __init__(self, sasl, username=None, password=None, identity='', **props):
        Mechanism.__init__(self, sasl)
        self.identity = identity
        self.username = username
        self.password = password

    def process_challenge(self, challenge=None):
        self._fetch_properties('username', 'password')
        self.complete = True
        auth_id = self.sasl.authorization_id or self.identity
        return b''.join((_b(auth_id), b'\x00', _b(self.username), b'\x00', _b(self.password)))

    def dispose(self):
        self.password = None
