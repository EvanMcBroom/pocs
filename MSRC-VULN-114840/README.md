# MSRC-VULN-114839

Microsoft Local Security Authority Subsystem Service (LSASS) memory corruption vulnerability.

### Notes

The `msv1_0` SSP allows users to submit protocol messages to it using the `LsaCallAuthenticationPackage` API. The SSP supports the undocumented `MsV1_0GetStrongCredentialKey` message which allows users outside of the LSASS process to supply pointers for the LSASS process to use. LSASS will not validate these pointers before they're used. Administrative users may pass invalid pointers to LSASS to interpret.

The bug allows users to effect LSASS regardless of if its running as a PPL. At best users may use the bug to crash a critical process (LSASS) and reboot the host. Using the dereference to gain arbitrary code execution may be possible but has not been proven.
The bug requires the `SeTcbPrivilege` privilege, which reduces the potential for abuse, and MSRC ultimately considered both to be by design.
