#include <Windows.h>

#pragma section(".code", execute,read,write)
#pragma comment(linker,"/MERGE:.text=.code")
#pragma comment(linker,"/MERGE:.data=.code")
#pragma comment(linker,"/SECTION:.code,ERW")
#pragma code_seg(".code")

#define VAR_DWORD(name)	__asm _emit 0x04 __asm _emit 0x04 \
						__asm _emit 0x04 __asm _emit 0x04

#define STR_DEF_04(name, a1, a2, a3, a4) __asm _emit a1 __asm _emit a2 \
										 __asm _emit a3 __asm _emit a4

#define SZ_FORMAT_STR	4
#define SZ_LIB_NAME		16



typedef int(*printfPtr)(const char * restrict, ...);
typedef HMODULE (*LoadLibraryAPtr)(LPCSTR lpLibFileName);
typedef FARPROC (*GetProcAddressPtr)(HMODULE hModule,LPCSTR lpProcName);

#pragma pack(1)
typedef struct _USER_MODE_ADDRESS_RESOLUTION
{
	unsigned char LoadLibraryA[SZ_LIB_NAME];
	unsigned char GetProcAddress[SZ_LIB_NAME];
} USER_MODE_ADDRESS_RESOLUTION;
#pragma pack(0)


#pragma pack(1)
typedef struct _ADDRESS_TABLE
{
	// address resolution
	USER_MODE_ADDRESS_RESOLUTION routines;

	// application specific
	unsigned char MSVCR90dll[SZ_LIB_NAME];
	unsigned char printfName[SZ_LIB_NAME];
	printfPtr printf; // printf ptr
	unsigned char formatStr[SZ_FORMAT_STR];
	unsigned long globalInteger;

} ADDRESS_TABLE;
#pragma pack()


unsigned long get_kernel32_base()
{
	unsigned long kernel32_address;
	_asm
	{
		xor ebx, ebx; // ebx = 0
		mov ebx, fs:[0x30]; // get PEB from TEB
		mov ebx, [ebx + 0x0C]; // get LDR from PEB
		mov ebx, [ebx + 0x14]; // get InMemoryOrderModuleList from LDR struct
		mov ebx, [ebx]; // flink (point to ntdll ModuleList)
		mov ebx, [ebx]; // flink (point to kernel32 ModuleList)
		mov ebx, [ebx + 0x10];  // point to dll base (InMemoryOrderList + 0x10 = DllBase)
		mov kernel32_address, ebx;
	}

	return (kernel32_address);
}


unsigned long address_table_storage()
{
	unsigned int table_address;
	__asm
	{
		call end_of_data; // save pointer to data on stack

		STR_DEF_04(LoadLibraryA, 'L', 'o', 'a', 'd');
		STR_DEF_04(LoadLibraryA, 'L', 'i', 'b', 'r');
		STR_DEF_04(LoadLibraryA, 'a', 'r', 'y', 'A');
		STR_DEF_04(LoadLibraryA, '\0', '\0', '\0', '\0');

		STR_DEF_04(GetProcAddress, 'G', 'e', 't', 'P');
		STR_DEF_04(GetProcAddress, 'r', 'o', 'c', 'A');
		STR_DEF_04(GetProcAddress, 'd', 'd', 'r', 'e');
		STR_DEF_04(GetProcAddress, 's', 's', '\0', '\0');

		STR_DEF_04(MSVCR90dll, 'c', 'r', 't', 'd');
		STR_DEF_04(MSVCR90dll, 'l', 'l', '.', 'd');
		STR_DEF_04(MSVCR90dll, 'l', 'l', '\0', '\0');
		STR_DEF_04(MSVCR90dll, '\0', '\0', '\0', '\0');

		STR_DEF_04(printfName, 'p', 'r', 'i', 'n');
		STR_DEF_04(printfName, 't', 'f', '\0', '\0');
		STR_DEF_04(printfName, '\0', '\0', '\0', '\0');
		STR_DEF_04(printfName, '\0', '\0', '\0', '\0');

		VAR_DWORD(printf);

		STR_DEF_04(formatStr, '%', 'X', '\n', '\0');
		
		VAR_DWORD(globalInteger);

	end_of_data:

		pop eax;
		mov table_address, eax;
	}

	return (table_address);
}


int compare(char *p1, char *p2)
{
	register const unsigned char *s1 = (const unsigned char *)p1;
	register const unsigned char *s2 = (const unsigned char *)p2;
	unsigned char c1, c2;

	do
	{
		c1 = (unsigned char)*s1++;
		c2 = (unsigned char)*s2++;
		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;

}


BOOL walk_export_list(unsigned long dll_base, DWORD *function_ptr, char *func_name)
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)dll_base;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)(dll_base + image_dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* image_data_directory = &(image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	DWORD descriptor_start_rva = image_data_directory->VirtualAddress;

	IMAGE_EXPORT_DIRECTORY* export_directory = (PIMAGE_EXPORT_DIRECTORY)(dll_base + descriptor_start_rva);

	char *dll_name = (char*)(dll_base + export_directory->Name);
	DWORD* address_of_names = (DWORD*)(dll_base + export_directory->AddressOfNames);
	DWORD* address_of_functions = (DWORD*)(dll_base + export_directory->AddressOfFunctions);
	WORD* address_of_ordinals = (WORD*)(dll_base + export_directory->AddressOfNameOrdinals);
	
	SIZE_T index, j;

	for (index = 0; index < export_directory->NumberOfNames; index++)
	{
		char* name;
		DWORD name_rva;
		WORD ordinal;

		name_rva = address_of_names[index];

		if (name_rva == 0)
			continue;

		name = (char *)(dll_base + name_rva);

		if (compare(name, func_name) == 0)
		{
			ordinal = address_of_ordinals[index];
			(*function_ptr) = (dll_base + address_of_functions[ordinal]);
			return TRUE;
		}

	}

	return FALSE;
}


void main()
{
	LoadLibraryAPtr loadlibraryA;
	GetProcAddressPtr getprocaddress;
	HMODULE msvcr90_dll_handle;

	unsigned long kernel32base = get_kernel32_base();

	ADDRESS_TABLE *address_table = (ADDRESS_TABLE*)address_table_storage();
		
	if (!walk_export_list(kernel32base, &loadlibraryA, address_table->routines.LoadLibraryA))
		return;

	msvcr90_dll_handle = loadlibraryA(address_table->MSVCR90dll);

	if (!walk_export_list(kernel32base, &getprocaddress, address_table->routines.GetProcAddress))
		return;

	address_table->printf = (printfPtr)getprocaddress(msvcr90_dll_handle, address_table->printfName);

	if (address_table->printf == NULL)
		return;
}
