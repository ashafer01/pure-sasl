from .mechanisms import server_mechanisms


class SASLServer(object):
    """
    Handles the server side of SASL - creating challenges and verifying
    responses.

    This should be instantiated when your server starts up. You can use
    available_mechanisms() to advertise the supported list of mechanism
    names to the client.

    A pseudo-tcp server will look something like this::

        >>> sasl = SASLServer('an.example.com', 'myproto')
        >>> def client_connected(reader, writer):
        ...     \"""Called when a new client connects to the server\"""
        ...     # assume the initial message includes the client's chosen mechanism
        ...     # decode_message() would separate the mechanism from 0 or more
        ...     # bytes for the initial client response
        ...     mechanism, response_bytes = decode_message(reader.read())
        ...
        ...     # begin the challenge-response exchange
        ...     sasl.begin(mechanism)
        ...     while True:
        ...         try:
        ...             challenge = sasl.process(response_bytes)
        ...         except SASLAuthenticationFailure as e:
        ...             print('Could not authenticate user: {}'.format(e))
        ...             return False
        ...         if challenge:
        ...             writer.write(challenge)
        ...         if sasl.complete:
        ...             # authentication has completed successfully
        ...             break
        ...         else:
        ...             # assume subsequent messages only contain the response
        ...             response_bytes = reader.read()
        ...     # end the challenge-response exchange ...
        ...     sasl_mech = sasl.end()
        ...
        ...     # begin application
        ...     # wrap/unwrap only needed for auth-int and auth-conf
        ...     # for auth QOP these will just pass through the input
        ...     print('Authenticated user: {0}'.format(sasl_mech.username))
        ...     while True:
        ...         data = reader.read()
        ...         data = sasl_mech.unwrap(data)
        ...         response = your_application(data)
        ...         response = sasl_mech.wrap(response)
        ...         writer.write(response)

    It's important that the ``sasl_mech`` returned by sasl.end() is only ever
    used with the client that created it.
    """
    def __init__(self, host, service, max_buffer=65536, **mech_props):
        self.host = host
        self.service = service
        self.max_buffer = max_buffer
        self._mech_props = mech_props
        self._mech = None

    @staticmethod
    def available_mechanisms():
        return list(server_mechanisms.keys())

    def begin(self, mech):
        self._mech = server_mechanisms[mech](self, **self._mech_props)

    def process(self, response):
        return self._mech.process_response(response)

    @property
    def complete(self):
        return self._mech.complete

    def end(self):
        mech = self._mech
        self._mech = None
        return mech
