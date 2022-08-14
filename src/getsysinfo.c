/*
BSD 2-Clause License

Copyright (c) 2021-2022, Mikhail Morozov
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wchar.h>

#define _WIN32_WINNT 0x0501

#include <Windows.h>

static USHORT g_machines[] = {
	0x1, 0x14c, 0x160, 0x162, 0x166, 0x168, 0x169, 0x184,
	0x1a2, 0x1a3, 0x1a4, 0x1a6, 0x1a8, 0x1c0, 0x1c2, 0x1c4, 0x1d3, 0x1f0,
	0x1f1, 0x200, 0x266, 0x284, 0x366, 0x466, 0x520, 0xcef, 0xebc, 0x8664,
	0x9041, 0xAA64, 0xC0EE
};

static void PrintWindowsDir(void);
static void PrintSystemDir(void);
static void PrintSysWOW64Dir(void);
static const wchar_t *GetMachineName(USHORT machine);
static void PrintIsWow64(void);
static void PrintWow64SupportedGuestMachines(void);
static void PrintSystemInfo(void);
static void PrintNativeSystemInfo(void);
static void PrintSystemInfoStruct(LPSYSTEM_INFO si);
static void PrintProcessorGroupInfo(void);

int main(void)
{
	PrintWindowsDir();
	PrintSystemDir();
	PrintSysWOW64Dir();
	PrintIsWow64();
	PrintWow64SupportedGuestMachines();
	PrintSystemInfo();
	PrintNativeSystemInfo();
	PrintProcessorGroupInfo();
	getc(stdin);

	return 0;
}

static void PrintWindowsDir(void)
{
	wchar_t *buf;
	UINT bufsize = MAX_PATH;
	UINT ret;

	buf = malloc((bufsize+1)*sizeof(wchar_t));
	if(!buf) return;

	ret = GetWindowsDirectoryW(buf, bufsize);
	if(ret > bufsize) {
 		wchar_t *_buf;

		bufsize = ret;

		_buf = realloc(buf, (bufsize+1)*sizeof(wchar_t));
		if(!_buf) {
			free(buf);
			return;
		} else
			buf = _buf;

		ret = GetWindowsDirectoryW(buf, bufsize);
		if(ret > bufsize) {
			free(buf);
			return;
		}
	}

	wprintf(L"Windows folder: %ls\n", buf);
}

static void PrintSystemDir(void)
{
	wchar_t *buf;
	UINT bufsize = MAX_PATH;
	UINT ret;

	buf = malloc((bufsize+1)*sizeof(wchar_t));
	if(!buf) return;

	ret = GetSystemDirectoryW(buf, bufsize);
	if(ret > bufsize) {
 		wchar_t *_buf;

		bufsize = ret;

		_buf = realloc(buf, (bufsize+1)*sizeof(wchar_t));
		if(!_buf) {
			free(buf);
			return;
		} else
			buf = _buf;

		ret = GetSystemDirectoryW(buf, bufsize);
		if(ret > bufsize) {
			free(buf);
			return;
		}
	}

	wprintf(L"System folder: %ls\n", buf);
}

typedef UINT (__stdcall *GetSystemWow64Directory2W_type)(LPWSTR lpBuffer, UINT uSize, WORD ImageFileMachineType);
static GetSystemWow64Directory2W_type GetSystemWow64Directory2W_funcptr = 0;

static void PrintSysWOW64Dir(void)
{
	wchar_t *buf;
	UINT bufsize = 65536;
	UINT ret;
	HANDLE kernel32_handle;

	kernel32_handle = GetModuleHandleW(L"kernelbase.dll");

	if(kernel32_handle)
		GetSystemWow64Directory2W_funcptr = (GetSystemWow64Directory2W_type)GetProcAddress(kernel32_handle, "GetSystemWow64Directory2W");

	buf = malloc((bufsize+1)*sizeof(wchar_t));
	if(!buf) return;

	if(GetSystemWow64Directory2W_funcptr) {
		size_t i;

		for(i = 0; i < sizeof(g_machines)/sizeof(USHORT); i++) {
			ret = GetSystemWow64Directory2W_funcptr(buf, bufsize + 1, g_machines[i]);

			if(!ret) continue;

			if(ret > bufsize) {
				wchar_t *_buf;

				_buf = realloc(buf, (ret+1)*sizeof(wchar_t));
				if(!_buf) {
					continue;
				} else {
					bufsize = ret;
					buf = _buf;
				}

				ret = GetSystemWow64Directory2W_funcptr(buf, bufsize+1, g_machines[i]);
				if(ret > bufsize) continue;
			}

			wprintf(L"WOW64 System folder for %ls: %ls\n", GetMachineName(g_machines[i]), buf);
		}
	} else {
		ret = GetSystemWow64DirectoryW(buf, bufsize);
		if(ret > bufsize) {
			wchar_t *_buf;

			bufsize = ret;

			_buf = realloc(buf, (bufsize+1)*sizeof(wchar_t));
			if(!_buf) {
				free(buf);
				return;
			} else
				buf = _buf;

			ret = GetSystemWow64DirectoryW(buf, bufsize);
			if(ret > bufsize) {
				free(buf);
				return;
			}
		}

		wprintf(L"WOW64 System folder: %ls\n", buf);
	}
}

static const wchar_t *GetMachineName(USHORT machine)
{
	switch(machine) {
		case 0x1:
			return L"Interacts with host and not a WOW64 guest"; // ???
		case 0x14c:
			return L"i386";
		case 0x160:
			return L"MIPS BE"; // Big-Endian
		case 0x162:
			return L"MIPS LE"; // Little-Endian
		case 0x166:
			return L"R4000";
		case 0x168:
			return L"R10000";
		case 0x169:
			return L"MIPS LE WCE v2";
		case 0x184:
			return L"ALPHA AXP";
		case 0x1a2:
			return L"SH3 LE";
		case 0x1a3:
			return L"SH3DSP";
		case 0x1a4:
			return L"SH3E LE";
		case 0x1a6:
			return L"SH4 LE";
		case 0x1a8:
			return L"SH5";
		case 0x1c0:
			return L"ARM";
		case 0x1c2:
			return L"ARM Thumb/Thumb-2 LE";
		case 0x1c4:
			return L"ARM Thumb-2 LE";
		case 0x1d3:
			return L"TAM33BD";
		case 0x1f0:
			return L"IBM PowerPC LE";
		case 0x1f1:
			return L"POWERPCFP";
		case 0x200:
			return L"IA64";
		case 0x266:
			return L"MIPS";
		case 0x284:
			return L"ALPHA AXP64";
		case 0x366:
			return L"MIPSFPU";
		case 0x466:
			return L"MIPSFPU16";
		case 0x520:
			return L"Infineon Tricore";
		case 0xcef:
			return L"CEF";
		case 0xebc:
			return L"EBC";
		case 0x8664:
			return L"AMD64";
		case 0x9041:
			return L"M32R LE";
		case 0xAA64:
			return L"ARM64 LE";
		case 0xC0EE:
			return L"CEE";
		case 0:
		default:
			return L"Unknown";
	}
}

typedef BOOL (__stdcall * IsWow64Process2_type)(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine);
static IsWow64Process2_type IsWow64Process2_funcptr = 0;

static void PrintIsWow64(void)
{
	bool printed = false;
	BOOL is_wow64_process = 0;
	USHORT process_machine = 0, native_machine = 0;
	HANDLE kernel32_handle;

	kernel32_handle = GetModuleHandleW(L"kernel32.dll");
	if(kernel32_handle)
		IsWow64Process2_funcptr = (IsWow64Process2_type)GetProcAddress(kernel32_handle, "IsWow64Process2");

	if(printed == false && IsWow64Process2_funcptr != 0)
		if(IsWow64Process2_funcptr(GetCurrentProcess(), &process_machine, &native_machine)) {
			printed = true;

			if(process_machine == native_machine || process_machine == 0) {
				wprintf(L"Process is not Wow64:\n");
				wprintf(L"\tprocess machine is %ls\n", GetMachineName(native_machine));
			} else {
				wprintf(L"Process is Wow64 (0x%hx on 0x%hx):\n", process_machine, native_machine);
				wprintf(L"\tprocess machine is %ls\n", GetMachineName(process_machine));
				wprintf(L"\tnative machine is %ls\n", GetMachineName(native_machine));
			}
		}


	if(printed == false)
		if(IsWow64Process(GetCurrentProcess(), &is_wow64_process)) {
			printed = true;

			if(is_wow64_process)
				wprintf(L"Process is Wow64\n");
			else
				wprintf(L"Process is not Wow64\n");
		}
}

typedef HRESULT (__stdcall *IsWow64GuestMachineSupported_type)(USHORT WowGuestMachine, BOOL *MachineIsSupported);
static IsWow64GuestMachineSupported_type IsWow64GuestMachineSupported_funcptr = 0;

static void PrintWow64SupportedGuestMachines(void)
{
	size_t i;
	HANDLE kernel32_handle;

	kernel32_handle = GetModuleHandleW(L"kernel32.dll");
	if(kernel32_handle)
		IsWow64GuestMachineSupported_funcptr = (IsWow64GuestMachineSupported_type)GetProcAddress(kernel32_handle, "IsWow64GuestMachineSupported");

	if(!IsWow64GuestMachineSupported_funcptr)
		return;

	for(i = 0; i < sizeof(g_machines)/sizeof(USHORT); i++) {
		HRESULT result;
		BOOL machine_is_supported = 0;

		result = IsWow64GuestMachineSupported_funcptr(g_machines[i], &machine_is_supported);
		if(result != S_OK) continue;

		if(machine_is_supported)
			wprintf(L"Supported WOW64 Guest Machine: %ls\n", GetMachineName(g_machines[i]));
	}

}

static void PrintSystemInfo(void)
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	wprintf(L"System info:\n");
	PrintSystemInfoStruct(&si);
}

static void PrintNativeSystemInfo(void)
{
	SYSTEM_INFO si;

	GetNativeSystemInfo(&si);
	wprintf(L"Native System info:\n");
	PrintSystemInfoStruct(&si);
}

#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

static void PrintSystemInfoStruct(LPSYSTEM_INFO si)
{
	wprintf(L"\tprocessor architecture: ");
	switch(si->wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			wprintf(L"AMD64\n");
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			wprintf(L"ARM\n");
			break;
		case PROCESSOR_ARCHITECTURE_ARM64:
			wprintf(L"ARM64\n");
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			wprintf(L"Intel Itanium (IA64)\n");
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			wprintf(L"x86\n");
			break;
		case PROCESSOR_ARCHITECTURE_UNKNOWN:
		default:
			wprintf(L"Unknown\n");
	}

	wprintf(L"\tpage size: %d\n", si->dwPageSize);
	wprintf(L"\tminimum app address: 0x%p\n", si->lpMinimumApplicationAddress);
	wprintf(L"\tmaximum app address: 0x%p\n", si->lpMaximumApplicationAddress);
	wprintf(L"\tactive processor mask: 0x%p\n", (void *)(si->dwActiveProcessorMask));
	wprintf(L"\tnumber of processors in current group: %d\n", si->dwNumberOfProcessors);
	wprintf(L"\tprocessor level: %hd\n", si->wProcessorLevel);
	wprintf(L"\tprocessor revision 0x%hx\n", si->wProcessorRevision);
}

typedef WORD (__stdcall *GetActiveProcessorGroupCount_type)(void);
static GetActiveProcessorGroupCount_type GetActiveProcessorGroupCount_funcptr = 0;

typedef DWORD (__stdcall *GetActiveProcessorCount_type)(WORD GroupNumber);
static GetActiveProcessorCount_type GetActiveProcessorCount_funcptr = 0;

void PrintProcessorGroupInfo(void)
{
	HANDLE kernel32_handle;
	
	kernel32_handle = GetModuleHandleW(L"kernel32.dll");
	if(!kernel32_handle) return;
	GetActiveProcessorGroupCount_funcptr = (GetActiveProcessorGroupCount_type)GetProcAddress(kernel32_handle, "GetActiveProcessorGroupCount");
	GetActiveProcessorCount_funcptr = (GetActiveProcessorCount_type)GetProcAddress(kernel32_handle, "GetActiveProcessorCount");
	
	if(GetActiveProcessorGroupCount_funcptr && GetActiveProcessorCount_funcptr) {
		WORD group_count, i;
		
		group_count = GetActiveProcessorGroupCount_funcptr();
		wprintf(L"Processor groups count: %hu\n", group_count);
		
		for(i = 0; i < group_count; i++) {
			DWORD processor_count;
			
			processor_count = GetActiveProcessorCount_funcptr(i);
			wprintf(L"\tGroup %hu has %u processors\n", i, processor_count);
		}
	}
}
