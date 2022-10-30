# Coerce MS-FAX

Remotely coerce a machine account to authenticate to a listening server and port via MS-FAX.

The MS-FAX server does not require WebClient to be running to connect to the arbitrary port.
The session signing negotiation flag will be set.
So the coercion would need to be combined with [an additional bug](https://www.thehacker.recipes/ad/movement/ntlm/relay#mic-message-integrity-code) to be used.
The issue was not reported to [MSRC](https://www.microsoft.com/en-us/msrc) because they do not consider authenticated coerced authentication attacks to be crossing a security boundary.

### Links

* [[MS-FAX] Section 4.6: Message Exchanges During Registering and Unregistering for Server Notifications](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fax/d59e7c8d-6fa2-4568-8542-33d27eef3af9)
