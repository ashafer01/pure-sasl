from .anonymous import AnonymousMechanism
from .plain import PlainMechanism
from .external import ExternalMechanism
from .cram_md5 import CramMD5Mechanism
from .digest_md5 import DigestMD5Mechanism
from .gssapi import GSSAPIMechanism, have_kerberos

#: Global registry mapping mechanism names to implementation classes.
mechanisms = dict((m.name, m) for m in (
    AnonymousMechanism,
    PlainMechanism,
    ExternalMechanism,
    CramMD5Mechanism,
    DigestMD5Mechanism))

if have_kerberos:
    mechanisms[GSSAPIMechanism.name] = GSSAPIMechanism
