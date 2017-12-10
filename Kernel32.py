from ctypes import *
from ctypes.wintypes import *

##
# Toolhelp Snapshot Flags
#
TH32CS_SNAPPROCESS = 0x00000002

##
# Memory Allocation Constants
#
MEM_RESERVE = 0x00002000
MEM_COMMIT  = 0x00001000

##
# Memory Protection Constants
#
PAGE_READWRITE         = 0x00000004
PAGE_EXECUTE_READWRITE = 0x00000040

##
# Process Security and Access Rights
#
DELETE             = 0x00010000
READ_CONTROL       = 0x00020000
WRITE_DAC          = 0x00040000
WRITE_OWNER        = 0x00080000
SYNCHRONIZE        = 0x00100000
PROCESS_ALL_ACCESS = ( DELETE       |
                       READ_CONTROL |
                       WRITE_DAC    |
                       WRITE_OWNER  |
                       SYNCHRONIZE  |
                       0xFFFF       # If version >= VISTA, else 0xFFF
                     )

##
# Path Constants
#
MAX_PATH = 260

##
# Structures
#
class tagPROCESSENTRY32(Structure):
    """Represent the tagPROCESSENTRY32 on TlHelp32.h"""
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ProcessID",       DWORD),
        ("th32DefaultHeapID",   LPVOID),
        ("th32ModuleID",        DWORD),
        ("cntThreads",          DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase",      LONG),
        ("dwFlags",             DWORD),
        ("szExeFile",           CHAR * MAX_PATH),
    ]

PROCESSENTRY32   = tagPROCESSENTRY32
LPPROCESSENTRY32 = LPVOID

##
# Function prototypes
#
Kernel32 = windll.kernel32

CloseHandle          = Kernel32.CloseHandle
CloseHandle.argtypes = [HMODULE]
CloseHandle.restype  = BOOL

CreateRemoteThread          = Kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [HANDLE, LPVOID, DWORD, LPVOID, LPVOID, DWORD, LPDWORD]
CreateRemoteThread.restype  = HANDLE

CreateToolhelp32Snapshot          = Kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype  = HANDLE

GetModuleHandleW          = Kernel32.GetModuleHandleW
GetModuleHandleW.argtypes = [LPCWSTR]
GetModuleHandleW.restype  = HMODULE

GetProcAddress          = Kernel32.GetProcAddress
GetProcAddress.argtypes = [HMODULE, LPCSTR]
GetProcAddress.restype  = LPVOID

LoadLibraryW          = Kernel32.LoadLibraryW
LoadLibraryW.argtypes = [LPCWSTR]
LoadLibraryW.restype  = HMODULE

OpenProcess          = Kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype  = HANDLE

Process32First          = Kernel32.Process32First
Process32First.argtypes = [HANDLE, LPPROCESSENTRY32]
Process32First.restype  = BOOL

Process32Next          = Kernel32.Process32Next
Process32Next.argtypes = [HANDLE, LPPROCESSENTRY32]
Process32Next.restype  = BOOL

VirtualAllocEx          = Kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD]
VirtualAllocEx.restype  = LPVOID

WriteProcessMemory          = Kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, DWORD, LPDWORD]
WriteProcessMemory.restype  = BOOL
