import hashlib
import hmac

from .base import Mechanism, _b


class CramMD5Mechanism(Mechanism):
    name = "CRAM-MD5"
    score = 20

    allows_anonymous = False
    uses_plaintext = False

    def __init__(self, sasl, username=None, password=None, **props):
        Mechanism.__init__(self, sasl)
        self.username = username
        self.password = password

    def process_challenge(self, challenge=None):
        if challenge is None:
            return None

        self._fetch_properties('username', 'password')
        mac = hmac.HMAC(key=_b(self.password), digestmod=hashlib.md5)
        mac.update(challenge)
        self.complete = True
        return b''.join((_b(self.username), b' ', _b(mac.hexdigest())))

    def dispose(self):
        self.password = None
