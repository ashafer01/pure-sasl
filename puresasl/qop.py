class QOP(object):

    AUTH = b'auth'
    AUTH_INT = b'auth-int'
    AUTH_CONF = b'auth-conf'

    all = (AUTH, AUTH_INT, AUTH_CONF)

    bit_map = {1: AUTH, 2: AUTH_INT, 4: AUTH_CONF}

    name_map = dict((bit, name) for name, bit in bit_map.items())

    @classmethod
    def names_from_bitmask(cls, byt):
        return set(name for bit, name in cls.bit_map.items() if bit & byt)

    @classmethod
    def flag_from_name(cls, name):
        return cls.name_map[name]
