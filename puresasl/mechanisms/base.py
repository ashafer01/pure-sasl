import sys

from ..exceptions import SASLError, SASLProtocolException
from ..qop import QOP

PY3 = sys.version_info[0] == 3
if PY3:
    def _b(s):
        return s.encode("utf-8")
else:
    def _b(s):
        return s


class Mechanism(object):
    """
    The base class for all mechanisms.
    """

    name = None
    """ The IANA registered name for the mechanism. """

    score = 0
    """ A relative security score where higher scores correspond
    to more secure mechanisms. """

    complete = False
    """ Set to True when SASL negotiation has completed succesfully. """

    has_initial_response = False

    allows_anonymous = True
    """ True if the mechanism allows for anonymous logins. """

    uses_plaintext = True
    """ True if the mechanism transmits sensitive information in plaintext. """

    active_safe = False
    """ True if the mechanism is safe against active attacks. """

    dictionary_safe = False
    """ True if the mechanism is safe against passive dictionary attacks. """

    qops = [QOP.AUTH]
    """ QOPs supported by the Mechanism """

    qop = QOP.AUTH
    """ Selected QOP """

    def __init__(self, sasl, **props):
        self.sasl = sasl

    def process_challenge(self, challenge=None):
        """
        Process a challenge request and return the response.

        :param challenge: A challenge issued by the server that
                          must be answered for authentication.
        """
        raise NotImplementedError()

    def wrap(self, outgoing):
        """
        Wrap an outgoing message intended for the SASL server. Depending
        on the negotiated quality of protection, this may result in the
        message being signed, encrypted, or left unaltered.
        """
        return outgoing

    def unwrap(self, incoming):
        """
        Unwrap a message from the SASL server. Depending on the negotiated
        quality of protection, this may check a signature, decrypt the message,
        or leave the message unaltered.
        """
        return incoming

    def dispose(self):
        """
        Clear all sensitive data, such as passwords.
        """
        pass

    def _fetch_properties(self, *properties):
        """
        Ensure this mechanism has the needed properties. If they haven't
        been set yet, the registered callback function will be called for
        each property to retrieve a value.
        """
        needed = [p for p in properties if getattr(self, p, None) is None]
        if needed and not self.sasl.callback:
            raise SASLError('The following properties are required, but a '
                            'callback has not been set: %s' % ', '.join(needed))

        for prop in needed:
            setattr(self, prop, self.sasl.callback(prop))

    def _pick_qop(self, server_qop_set):
        """
        Choose a quality of protection based on the user's requirements,
        what the server supports, and what the mechanism supports.
        """
        user_qops = set(_b(qop) if isinstance(qop, str) else qop for qop in self.sasl.qops)  # normalize user-defined config
        supported_qops = set(self.qops)
        available_qops = user_qops & supported_qops & server_qop_set
        if not available_qops:
            user = b', '.join(user_qops).decode('ascii')
            supported = b', '.join(supported_qops).decode('ascii')
            offered = b', '.join(server_qop_set).decode('ascii')
            raise SASLProtocolException("Your requested quality of "
                                        "protection is one of (%s), the server is "
                                        "offering (%s), and %s supports (%s)" % (user, offered, self.name, supported))
        else:
            for qop in (QOP.AUTH_CONF, QOP.AUTH_INT, QOP.AUTH):
                if qop in available_qops:
                    self.qop = qop
                    break
