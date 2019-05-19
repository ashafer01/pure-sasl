from .base import Mechanism, _b
from ..exceptions import *


class PlainMechanism(Mechanism):
    """
    A plaintext user/password based mechanism with client and server support
    Defined in RFC 4616

    Required and optional keyword arguments are listed below. These should be
    passed to SASLClient or SASLServer

      Client required:
        username=
        password=
      Client optional:
        identity=""

      Server required:
        check_password=
          Accepts a function which must accept arguments (username, password),
          and raise a SASLAuthenticationFailure if the user does not exist or
          if the password is incorrect. Return value is ignored.
    """
    name = 'PLAIN'
    score = 1

    allows_anonymous = False

    def __init__(self, sasl, username=None, password=None, identity='', **props):
        Mechanism.__init__(self, sasl)
        self.identity = identity
        self.username = username
        self.password = password
        self._check_password = props.get('check_password')

    def process_challenge(self, challenge=None):
        self._fetch_properties('username', 'password')
        self.complete = True
        auth_id = self.sasl.authorization_id or self.identity
        return b'\x00'.join((_b(auth_id), _b(self.username), _b(self.password)))

    def dispose(self):
        self.password = None

    def process_response(self, response):
        self.complete = False
        authzid, authcid, password = response.split(b'\x00')
        if self._check_password is not None:
            self._check_password(authcid, password)
            self.identity = authzid.decode('utf-8')
            self.username = authcid.decode('utf-8')
            self.complete = True
            return
        else:
            raise SASLError('No check_password function defined for PLAIN')
