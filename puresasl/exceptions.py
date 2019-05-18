class SASLError(Exception):
    """
    Typically represents a user error in configuration or usage of the
    SASL client or mechanism.
    """
    pass


class SASLProtocolException(Exception):
    """
    Raised when an error occurs while communicating with the SASL server
    or the client and server fail to agree on negotiated properties such
    as quality of protection.
    """
    pass


class SASLAuthenticationFailure(Exception):
    """
    Raised when a server declines to authenticate a client
    """
    pass


class SASLWarning(Warning):
    """
    Emitted in potentially fatal circumstances.
    """
    pass
