#pragma once
#ifndef PROCESS_DEBUGGER_H
#define PROCESS_DEBUGGER_H

#include "common.h"
#include "process_injector.h"
#include "ARC4.h"

class process_debugger_t
{
public:
	process_debugger_t(const char* path_to_file);
	~process_debugger_t();

	bool start_given_process_to_debug();

	bool start_debugging();


private:
	// private methods
	void process_events();


	// Information for create process
	std::string path_to_file_;
	STARTUPINFOA startup_info_process;
	PROCESS_INFORMATION proc_info_process;

	// debugger events
	DEBUG_EVENT debug_event;
	std::uint32_t waiting_time;
	std::uint32_t continue_debug_status;

	// context
#ifndef WIN64
	CONTEXT context;
#else
	CONTEXT context_x64;
	WOW64_CONTEXT context_x86;
#endif // !WIN64

	// injector
	process_injector_t* process_injector;
	uint8_t* buffer_data;
	ARC4 arc4;
};


#endif // !PROCESS_DEBUGGER_H
