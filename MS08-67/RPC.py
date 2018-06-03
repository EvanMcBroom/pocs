# -*- coding: utf-8 -*-

"""
Remote procedure code

References:
  https://publications.opengroup.org/c706
  http://pubs.opengroup.org/onlinepubs/9629399/
  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15
"""

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.smb import SMB
from struct import pack
from random import randint

PackWString = lambda s: s.encode('utf-16-le')
PackDWORD = lambda d: pack('<I', d)
PackList = lambda l, method: ''.join(method(_) for _ in l)

class NDR():
    @staticmethod
    def pad(s):
        if((len(s) % 4) == 0):
            return s
        return s + '\x00'*(4 - (len(s) % 4))

    @staticmethod
    def Byte(b):
        return pack('<B', b)

    @staticmethod
    def Short(s):
        return pack('<H', s)

    @staticmethod
    def Long(l):
        return pack('<I', l)

    @staticmethod
    def String(s):
        l = len(s)
        return NDR.pad(pack("<3I", l, 0, l) + s)

    @staticmethod
    def WString(s, Convert=True):
        if(Convert):
            s = PackWString(s)
        l = (len(s) / 2)
        return NDR.pad(pack("<3I", l, 0, l) + s)

    @staticmethod
    def UniqueWString(s, Convert=True):
        if(Convert):
            s = PackWString(s)
        l = (len(s) / 2)
        return NDR.pad(pack("<4I", randint(0, 0xffffffff), l, 0, l) + s)


def DCE(transport, timeout=2):
    try:
        t = DCERPCTransportFactory(transport)
        t.set_connect_timeout(int(timeout)) 
        d = t.get_dce_rpc()
        d.connect()
        return d
    except Exception, e:
        print('%s: %s' % (transport, str(e)))