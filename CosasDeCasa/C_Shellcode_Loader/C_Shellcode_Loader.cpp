
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

BOOL getShCodeParameters(BYTE* buffer, DWORD* offset, DWORD* size);
BOOL checkDosHeader(BYTE* buffer, DWORD* ntHeaderAddress);
BOOL digestNTHeaders(DWORD ntHeaderAddress, DWORD* nSections, DWORD* sectionTableAddress);
BOOL AllocateMemory(DWORD* shCodeAddress, DWORD sizeToAllocate, BYTE* bytesSh);

int main(int argc, const char *argv[])
{
	if (argc != 2)
	{
		printf("USAGE: %s <file_with_shellcode>\n", argv[0]);
		return 1;
	}

	HANDLE openedFile;
	DWORD fileSize, shellOffset, shellSize, shCodeAddress;
	BYTE* fileBuffer, *shellBuffer;
	DWORD oldProtection;



	openedFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (openedFile == INVALID_HANDLE_VALUE)
	{
		printf("[main]: failed open file\n");
		return 1;
	}

	fileSize = GetFileSize(openedFile, NULL);

	fileBuffer = (BYTE*)malloc(fileSize);

	if (!ReadFile(openedFile, (LPVOID)fileBuffer, fileSize, (LPDWORD)&fileSize, NULL))
	{
		printf("[main]: error reading file\n");
		CloseHandle(openedFile);
		free(fileBuffer);
		return 1;
	}

	if (!getShCodeParameters(fileBuffer, &shellOffset, &shellSize))
	{
		printf("[main]: error getting parameters\n");
		CloseHandle(openedFile);
		free(fileBuffer);
		return 1;
	}

	free(fileBuffer);

	SetFilePointer(openedFile, shellOffset, NULL, FILE_BEGIN);

	shellBuffer = (BYTE*)malloc(shellSize);

	if (!ReadFile(openedFile, shellBuffer, shellSize, &shellSize, NULL))
	{
		printf("[main]: error reading shellcode\n");
		CloseHandle(openedFile);
		free(shellBuffer);
		return 1;
	}

	//[1] - allocate memory for shellcode
	if (!AllocateMemory(&shCodeAddress, shellSize, shellBuffer))
	{
		printf("[main]: error allocating memory\n");
		CloseHandle(openedFile);
		free(shellBuffer);
		return 1;
	}

	//[2] - execute shellcode
	printf("[main]: shCodeAddress=%X\n", shCodeAddress);

	if (!VirtualProtect((LPVOID)shCodeAddress, shellSize, PAGE_EXECUTE_READWRITE, &oldProtection))
	{
		printf("[main]: error modifying protections 0x%X\n", GetLastError());
		CloseHandle(openedFile);
		free(shellBuffer);
		return 1;
	}

	__asm
	{
		mov edx, shCodeAddress; //mov address to edx
		call edx; // call function
	}

	//[3] - cleanup
	printf("[main]: cleanup\n");
	VirtualFree((void*)shCodeAddress, 0, MEM_RELEASE);
	CloseHandle(openedFile);
	free(shellBuffer);
	return 0;
}


BOOL getShCodeParameters(BYTE* buffer, DWORD* offset, DWORD* size)
{
	BOOL ok;
	DWORD dosHeaderAddress;
	DWORD ntHeaderAddress;
	DWORD nSections;
	DWORD secionTableAddress;
	DWORD index;
	IMAGE_SECTION_HEADER* sectionHeader;

	dosHeaderAddress = (DWORD)buffer;
	ok = checkDosHeader(buffer, &ntHeaderAddress);

	if (!ok)
	{
		printf("[getShCodeParameters]: Header check failed\n");
		return (FALSE);
	}

	ok = digestNTHeaders(ntHeaderAddress, &nSections, &secionTableAddress);

	if (!ok)
	{
		printf("[getShCodeParameters]: NT Header check failed\n");
		return (FALSE);
	}

	// iterate through section headers

	sectionHeader = (IMAGE_SECTION_HEADER*)secionTableAddress;
	for (index = 0; index < nSections; index++)
	{
		printf("[getShCodeParameters]: section %d\n", index);

		if 
		(
			sectionHeader[index].Name[0] == '.' &&
			sectionHeader[index].Name[1] == 'c' &&
			sectionHeader[index].Name[2] == 'o' &&
			sectionHeader[index].Name[3] == 'd' &&
			sectionHeader[index].Name[4] == 'e'
		)
		{
			printf("[getShCodeParameters]: found .code\n");
			*offset = sectionHeader[index].PointerToRawData;
			*size = sectionHeader[index].SizeOfRawData;
			printf("[getShCodeParameters]: call success\n");
			return (TRUE);
		}
	}

	printf("[getShCodeParameters]: Couldn't find .code section\n");
	return (FALSE);
}


BOOL checkDosHeader(BYTE* buffer, DWORD* ntHeaderAddress)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[checkDosHeader]: Error magic value not correct\n");
		*ntHeaderAddress = 0;
		return (FALSE);
	}

	*ntHeaderAddress = (DWORD)buffer + dos_header->e_lfanew;
	return (TRUE);
}


BOOL digestNTHeaders(DWORD ntHeaderAddress, DWORD* nSections, DWORD* sectionTableAddress)
{
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)ntHeaderAddress;

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[digestNTHeaders]: NT Signature not correct\n");
		*nSections = 0;
		*sectionTableAddress = 0;
		return (FALSE);
	}

	*nSections = nt_headers->FileHeader.NumberOfSections;
	*sectionTableAddress = (ntHeaderAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);
	return (TRUE);
}


BOOL AllocateMemory(DWORD* shCodeAddress, DWORD sizeToAllocate, BYTE* bytesSh)
{
	BYTE* memoryArray;
	DWORD index;

	// allocate memory to store shellcode
	printf("[AllocateMemory]: allocating %d bytes\n", sizeToAllocate);
	*shCodeAddress = (DWORD)VirtualAlloc
	(
		NULL,
		sizeToAllocate,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (*shCodeAddress == (DWORD)NULL)
	{
		printf("[AllocateMemory]: VirtualAlloc() failed\n");
		return (FALSE);
	}

	// copy shellcode into allocate memory
	memoryArray = (BYTE*)(*shCodeAddress);
	for (index = 0; index < sizeToAllocate; index++)
	{
		memoryArray[index] = bytesSh[index];
	}
	printf("[AllocateMemory] call success\n");
	return (TRUE);
}