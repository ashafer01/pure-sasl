import hashlib
import random
import os
import sys
from base64 import b64encode

from .base import Mechanism
from ..exceptions import *
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
    return b'"' + text.replace(b'\\', b'\\\\').replace(b'"', b'\\"').replace(b'<', b'\\<').replace(b'>', b'\\>') + b'"'


class DigestMD5Mechanism(Mechanism):
    """
    DIGEST-MD5 SASL mechanism with client and server support

    Required and optional keyword arguments are listed below. These should be
    passed to SASLClient or SASLServer

      Client required:
        username=
        password=
      Client optional:
        realm=""
        authorization_id=None

      Server required:
        get_password_hash=
          Accepts a function which must retrieve and return the stored password
          hash, specifially:
            H( { username-value, ":", realm-value, ":", passwd } )
          as defined in RFC 2831 sec 2.1.2.1
          The function will be passed 2 arguments:
            (username, realm)
          It must raise SASLAuthenticationFailure if the username or realm do
          not exist.
      Server optional:
        realm=""
    """
    name = "DIGEST-MD5"
    score = 30

    allows_anonymous = False
    uses_plaintext = False

    def __init__(self, sasl, **props):
        Mechanism.__init__(self, sasl)
        self.username = props.get('username')
        self.password = props.get('password')
        self.authorization_id = props.get('authorization_id', getattr(sasl, 'authorization_id', None))
        self.realm = props.get('realm', b'')
        self._get_password_hash = props.get('get_password_hash')

        self._digest_uri = (
                to_bytes(sasl.service) + b'/' + to_bytes(sasl.host))
        self._a2 = b'AUTHENTICATE:' + self._digest_uri

        self.nc = 0

    def dispose(self):
        self._digest_uri = None

        self.password = None
        self.key_hash = None
        self.realm = None
        self.nonce = None
        self.cnonce = None
        self.nc = 0

    def response(self):
        required_props = ['username']
        if not getattr(self, 'key_hash', None):
            required_props.append('password')
        self._fetch_properties(*required_props)

        if self.nc == 0:
            self.cnonce = to_bytes('%s' % random.random())[2:]
        self.nc += 1

        resp = {
            'qop': self.qop,
            'realm': quote(self.realm),
            'username': quote(to_bytes(self.username)),
            'nonce': quote(self.nonce),
            'digest-uri': quote(self._digest_uri),
            'cnonce': quote(self.cnonce),
            'nc': to_bytes('%08x' % self.nc),
        }

        a2 = self._a2
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

    @staticmethod
    def gen_key_hash(username, password, realm=''):
        _key_hash = hashlib.md5()
        user = to_bytes(username)
        password = to_bytes(password)
        realm = to_bytes(realm)
        kh = user + b':' + realm + b':' + password
        _key_hash.update(kh)
        return _key_hash.digest()

    def gen_hash(self, a2, key_hash=None):
        if key_hash is None:
            key_hash = getattr(self, 'key_hash', None)
        if not key_hash:
            key_hash = self.gen_key_hash(self.username, self.password, self.realm)
            self.key_hash = key_hash

        a1 = hashlib.md5(key_hash)
        a1h = b':' + self.nonce + b':' + self.cnonce
        a1.update(a1h)
        if self.authorization_id:
            a1.update(b':' + to_bytes(self.authorization_id))
        response = hashlib.md5()
        _a1 = a1.digest()
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

    def process_challenge(self, challenge=None):
        if challenge is None:
            needed = ['username', 'realm', 'nonce', 'key_hash',
                      'nc', 'cnonce', 'qops']
            if all(getattr(self, p, None) is not None for p in needed):
                return self.response()
            else:
                return None

        challenge_dict = self.parse_challenge(challenge)
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

    # server methods

    def challenge(self):
        """Create a new challenge on the server side"""
        if self.nc < 1:
            self.nonce = b64encode(os.urandom(128))
        self.complete = False
        challenge_dict = {
            'realm': self.realm,
            'nonce': self.nonce,
            'qop': QOP.AUTH,
            'charset': 'utf-8',
            'algorithm': 'md5-sess',
        }
        challenge_list = []
        for key, val in challenge_dict.items():
            challenge_list.append(to_bytes(key) + b'=' + quote(val))
        self.nc += 1
        return b','.join(challenge_list)

    def get_password_hash(self, username):
        if self._get_password_hash is not None:
            return self._get_password_hash(username, self.realm)
        raise SASLError('get_password hash function unavailable; cannot validate response')

    def process_response(self, response):
        """Verify client's step 2 response to the server"""
        if self.nc < 1:
            return self.challenge()
        response_dict = self.parse_challenge(response)
        try:
            if self.nc != int(response_dict['nc'], 16):
                raise SASLAuthenticationFailure('nc mismatch, possible replay attack')

            response_dict.setdefault('realm', b'')
            for attr in 'nonce', 'realm':
                if getattr(self, attr) != response_dict[attr]:
                    raise SASLAuthenticationFailure('%s mismatch' % attr)

            if self.nc == 1:
                self.cnonce = response_dict['cnonce']
            response_dict.setdefault('qop', QOP.AUTH)
            if response_dict['qop'] != QOP.AUTH:
                raise SASLAuthenticationFailure('Invalid or unsupported qop %s' % response_dict['qop'])
            if self._digest_uri != response_dict.get('digest-uri', self._digest_uri):
                raise SASLAuthenticationFailure('digest-uri mismatch')

            username = response_dict['username']
            key_hash = self.get_password_hash(username)
            expected_response = self.gen_hash(self._a2, key_hash)
            if response_dict['response'] != expected_response:
                raise SASLAuthenticationFailure('Bad credentials')

            self.complete = True
            self.username = username
            return to_bytes('rspauth') + b'=' + self.gen_hash(b':' + self._digest_uri, key_hash)
        except KeyError as e:
            raise SASLAuthenticationFailure('missing required response key %s' % e.args[0])
