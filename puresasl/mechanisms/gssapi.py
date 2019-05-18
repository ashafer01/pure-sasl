import base64
import platform
import struct

from .base import Mechanism, _b
from ..exceptions import SASLProtocolException
from ..qop import QOP

if platform.system() == 'Windows':
    try:
        import winkerberos as kerberos
        # Fix for different capitalisation in winkerberos method name
        kerberos.authGSSClientUserName = kerberos.authGSSClientUsername
        have_kerberos = True
    except ImportError:
        have_kerberos = False
else:
    try:
        import kerberos
        have_kerberos = True
    except ImportError:
        have_kerberos = False


class GSSAPIMechanism(Mechanism):
    name = 'GSSAPI'
    score = 100
    qops = QOP.all

    allows_anonymous = False
    uses_plaintext = False
    active_safe = True

    def __init__(self, sasl, principal=None, **props):
        Mechanism.__init__(self, sasl)
        self.user = None
        self._have_negotiated_details = False
        self.host = self.sasl.host
        self.service = self.sasl.service
        self.principal = principal
        self._fetch_properties('host', 'service')

        krb_service = '@'.join((self.service, self.host))
        try:
            _, self.context = kerberos.authGSSClientInit(service=krb_service,
                                                         principal=self.principal)
        except TypeError:
            if self.principal is not None:
                raise Exception("Error: kerberos library does not support principal.")
            _, self.context = kerberos.authGSSClientInit(service=krb_service)

    def process_challenge(self, challenge=None):
        if not self._have_negotiated_details:
            kerberos.authGSSClientStep(self.context, '')
            _negotiated_details = kerberos.authGSSClientResponse(self.context)
            self._have_negotiated_details = True
            return base64.b64decode(_negotiated_details)

        challenge = base64.b64encode(challenge).decode('ascii')  # kerberos methods expect strings, not bytes
        if self.user is None:
            ret = kerberos.authGSSClientStep(self.context, challenge)
            if ret == kerberos.AUTH_GSS_COMPLETE:
                self.user = kerberos.authGSSClientUserName(self.context)
                return b''
            else:
                response = kerberos.authGSSClientResponse(self.context)
                if response:
                    response = base64.b64decode(response)
                else:
                    response = b''
            return response

        kerberos.authGSSClientUnwrap(self.context, challenge)
        data = kerberos.authGSSClientResponse(self.context)
        plaintext_data = base64.b64decode(data)
        if len(plaintext_data) != 4:
            raise SASLProtocolException("Bad response from server")  # todo: better message

        word, = struct.unpack('!I', plaintext_data)
        qop_bits = word >> 24
        max_length = word & 0xffffff
        server_offered_qops = QOP.names_from_bitmask(qop_bits)
        self._pick_qop(server_offered_qops)

        self.max_buffer = min(self.sasl.max_buffer, max_length)

        """
        byte 0: the selected qop. 1==auth, 2==auth-int, 4==auth-conf
        byte 1-3: the max length for any buffer sent back and forth on
            this connection. (big endian)
        the rest of the buffer: the authorization user name in UTF-8 -
            not null terminated.
        """
        auth_id = self.sasl.authorization_id or self.user
        l = len(auth_id)
        fmt = '!I' + str(l) + 's'
        word = QOP.flag_from_name(self.qop) << 24 | self.max_buffer
        out = struct.pack(fmt, word, _b(auth_id),)

        encoded = base64.b64encode(out).decode('ascii')

        kerberos.authGSSClientWrap(self.context, encoded)
        response = kerberos.authGSSClientResponse(self.context)
        self.complete = True
        return base64.b64decode(response)

    def wrap(self, outgoing):
        if self.qop != QOP.AUTH:
            outgoing = base64.b64encode(outgoing)
            if self.qop == QOP.AUTH_CONF:
                protect = 1
            else:
                protect = 0
            kerberos.authGSSClientWrap(self.context, outgoing, None, protect)
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return outgoing

    def unwrap(self, incoming):
        if self.qop != QOP.AUTH:
            incoming = base64.b64encode(incoming).decode('ascii')
            kerberos.authGSSClientUnwrap(self.context, incoming)
            conf = kerberos.authGSSClientResponseConf(self.context)
            if 0 == conf and self.qop == QOP.AUTH_CONF:
                raise Exception("Error: confidentiality requested, but not honored by the server.")
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return incoming

    def dispose(self):
        kerberos.authGSSClientClean(self.context)
