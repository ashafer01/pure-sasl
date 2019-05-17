import hashlib
import random
import sys

from .base import Mechanism
from ..exceptions import SASLProtocolException
from ..qop import QOP


def to_bytes(text):
    """
    Convert Unicode text to UTF-8 encoded bytes.

    Since Python 2.6+ and Python 3+ have similar but incompatible
    signatures, this function unifies the two to keep code sane.

    :param text: Unicode text to convert to bytes
    :rtype: bytes (Python3), str (Python2.6+)
    """
    if sys.version_info < (3, 0):
        import __builtin__
        return __builtin__.bytes(text)
    else:
        import builtins
        if isinstance(text, builtins.bytes):
            # We already have bytes, so do nothing
            return text
        if isinstance(text, list):
            # Convert a list of integers to bytes
            return builtins.bytes(text)
        else:
            # Convert UTF-8 text to bytes
            return builtins.bytes(str(text), encoding='utf-8')


def quote(text):
    """
    Enclose in quotes and escape internal slashes and double quotes.

    :param text: A Unicode or byte string.
    """
    text = to_bytes(text)
    return b'"' + text.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'


class DigestMD5Mechanism(Mechanism):

    name = "DIGEST-MD5"
    score = 30

    allows_anonymous = False
    uses_plaintext = False

    def __init__(self, sasl, username=None, password=None, **props):
        Mechanism.__init__(self, sasl)
        self.username = username
        self.password = password

        self._digest_uri = None
        self._a1 = None

    def dispose(self):
        self._digest_uri = None
        self._a1 = None

        self.password = None
        self.key_hash = None
        self.realm = None
        self.nonce = None
        self.cnonce = None
        self.nc = 0

    def wrap(self, outgoing):
        return outgoing

    def unwrap(self, incoming):
        return incoming

    def response(self):
        required_props = ['username']
        if not getattr(self, 'key_hash', None):
            required_props.append('password')
        self._fetch_properties(*required_props)

        resp = {}
        resp['qop'] = self.qop

        if getattr(self, 'realm', None) is not None:
            resp['realm'] = quote(self.realm)

        resp['username'] = quote(to_bytes(self.username))
        resp['nonce'] = quote(self.nonce)
        if self.nc == 0:
            self.cnonce = to_bytes('%s' % random.random())[2:]
        resp['cnonce'] = quote(self.cnonce)
        self.nc += 1
        resp['nc'] = to_bytes('%08x' % self.nc)

        self._digest_uri = (
                to_bytes(self.sasl.service) + b'/' + to_bytes(self.sasl.host))
        resp['digest-uri'] = quote(self._digest_uri)

        a2 = b'AUTHENTICATE:' + self._digest_uri
        if self.qop != QOP.AUTH:
            a2 += b':00000000000000000000000000000000'
            resp['maxbuf'] = b'16777215'  # 2**24-1
        resp['response'] = self.gen_hash(a2)
        return b','.join(
            [
                to_bytes(k) + b'=' + to_bytes(v)
                for k, v in resp.items()
            ]
        )

    @staticmethod
    def parse_challenge(challenge):
        """Parse a digest challenge message.

        :param ``bytes`` challenge:
            Challenge message from the server, in bytes.
        :returns:
            ``dict`` of ``str`` keyword to ``bytes`` values.
        """
        ret = {}
        var = b''
        val = b''
        in_var = True
        in_quotes = False
        new = False
        escaped = False
        for c in challenge:
            if sys.version_info[0] == 3:
                c = to_bytes([c])
            if in_var:
                if c.isspace():
                    continue
                if c == b'=':
                    in_var = False
                    new = True
                else:
                    var += c
            else:
                if new:
                    if c == b'"':
                        in_quotes = True
                    else:
                        val += c
                    new = False
                elif in_quotes:
                    if escaped:
                        escaped = False
                        val += c
                    else:
                        if c == b'\\':
                            escaped = True
                        elif c == b'"':
                            in_quotes = False
                        else:
                            val += c
                else:
                    if c == b',':
                        if var:
                            ret[var.decode('ascii')] = val
                        var = b''
                        val = b''
                        in_var = True
                    else:
                        val += c
        if var:
            ret[var.decode('ascii')] = val
        return ret

    def gen_hash(self, a2):
        if not getattr(self, 'key_hash', None):
            key_hash = hashlib.md5()
            user = to_bytes(self.username)
            password = to_bytes(self.password)
            realm = to_bytes(self.realm)
            kh = user + b':' + realm + b':' + password
            key_hash.update(kh)
            self.key_hash = key_hash.digest()

        a1 = hashlib.md5(self.key_hash)
        a1h = b':' + self.nonce + b':' + self.cnonce
        a1.update(a1h)
        response = hashlib.md5()
        self._a1 = a1.digest()
        rv = to_bytes(a1.hexdigest().lower())
        rv += b':' + self.nonce
        rv += b':' + to_bytes('%08x' % self.nc)
        rv += b':' + self.cnonce
        rv += b':' + self.qop
        rv += b':' + to_bytes(hashlib.md5(a2).hexdigest().lower())
        response.update(rv)
        return to_bytes(response.hexdigest().lower())

    def authenticate_server(self, cmp_hash):
        a2 = b':' + self._digest_uri
        if self.qop != QOP.AUTH:
            a2 += b':00000000000000000000000000000000'
        if self.gen_hash(a2) != cmp_hash:
            raise SASLProtocolException('Invalid server auth response')

    def process(self, challenge=None):
        if challenge is None:
            needed = ['username', 'realm', 'nonce', 'key_hash',
                      'nc', 'cnonce', 'qops']
            if all(getattr(self, p, None) is not None for p in needed):
                return self.response()
            else:
                return None

        challenge_dict = DigestMD5Mechanism.parse_challenge(challenge)
        if 'rspauth' in challenge_dict:
            self.authenticate_server(challenge_dict['rspauth'])
            self.complete = True
            return None

        if 'realm' not in challenge_dict:
            self._fetch_properties('realm')
            challenge_dict['realm'] = self.realm

        for key in ('nonce', 'realm'):
            # TODO: rfc2831#section-2.1.1 realm: "Multiple realm directives are
            # allowed, in which case the user or client must choose one as the
            # realm for which to supply to username and password"
            # TODO: rfc2831#section-2.1.1 nonce: "This directive is required
            # and MUST appear exactly once; if not present, or if multiple
            # instances are present, the client should abort the authentication
            # exchange"
            if key in challenge_dict:
                setattr(self, key, challenge_dict[key])

        self.nc = 0
        if 'qop' in challenge_dict:
            server_offered_qops = [
                x.strip() for x in challenge_dict['qop'].split(b',')
            ]
        else:
            server_offered_qops = [QOP.AUTH]
        self._pick_qop(set(server_offered_qops))

        if 'maxbuf' in challenge_dict:
            self.max_buffer = min(
                self.sasl.max_buffer, int(challenge_dict['maxbuf']))

        # TODO: rfc2831#section-2.1.1 algorithm: This directive is required and
        # MUST appear exactly once; if not present, or if multiple instances
        # are present, the client should abort the authentication exchange.
        return self.response()
