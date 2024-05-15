# ChangeMachinePassword

Microsoft Local Security Authority Subsystem Service (LSASS) memory corruption vulnerability.

### Notes

The `kerberos` SSP allows users to submit protocol messages to it using the `LsaCallAuthenticationPackage` API.
The SSP supports the undocumented `KerbChangeMachinePassword` message which allows users outside of the LSASS process to supply pointers for the LSASS process to use.
LSASS will only validate if these pointers are not NULL before they're used.
Administrative users may pass invalid pointers to LSASS to interpret.

The bug allows users to effect LSASS regardless of if its running as a PPL.
At best users may use the bug to crash a critical process (LSASS) and reboot the host.
Using the dereference to gain arbitrary code execution may be possible but has not been proven.

The bug requires the `SeTcbPrivilege` privilege.
The issue was not reported to [MSRC](https://www.microsoft.com/en-us/msrc) because they do not consider local attacks that require `SeTcbPrivilege` to be crossing a security boundary.
