#include "common.h"
#include "process_debugger.h"
#include "process_injector.h"

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

	process_debugger_t proc_debugger(path);

	if (!proc_debugger.start_given_process_to_debug())
		return -1;

	proc_debugger.start_debugging();

}