from .mechanisms import server_mechanisms


class SASLServer(object):
    def __init__(self, host, service, **mech_props):
        self.host = host
        self.service = service
        self._mech_props = mech_props
        self._mech = None

    @staticmethod
    def available_mechanisms():
        return list(server_mechanisms.keys())

    def set_mechanism(self, mech):
        self._mech = server_mechanisms[mech](**self._mech_props)

    def challenge(self):
        return self._mech.challenge()

    def process(self, response):
        return self._mech.process_response(response)
