#include "process_debugger.h"

extern std::string key;

extern uint64_t file_size;

extern uint8_t encrypted_file[];

static bool first_breakpoint = true;

std::string GetFileNameFromHandle(HANDLE hFile)
{
	BOOL bSuccess = FALSE;
	char pszFilename[MAX_PATH + 1];
	HANDLE hFileMap;
	const std::uint32_t BUFSIZE = 512;

	std::string strFilename;

	// Get the file size.
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

	if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
	{
		return "";
	}

	// Create a file mapping object.
	hFileMap = CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,
		1,
		NULL);

	if (hFileMap)
	{
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem)
		{
			if (GetMappedFileNameA(GetCurrentProcess(),
				pMem,
				pszFilename,
				MAX_PATH))
			{

				// Translate path with device name to drive letters.
				char szTemp[BUFSIZE];
				szTemp[0] = '\0';

				if (GetLogicalDriveStringsA(BUFSIZE - 1, szTemp))
				{
					char szName[MAX_PATH];
					char szDrive[3] = " :";
					BOOL bFound = FALSE;
					char* p = szTemp;

					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if (QueryDosDeviceA(szDrive, szName, MAX_PATH))
						{
							size_t uNameLen = strlen(szName);

							if (uNameLen < MAX_PATH)
							{
								bFound = _strnicmp(pszFilename, szName,
									uNameLen) == 0;

								if (bFound)
								{
									strFilename = szDrive;
									strFilename += (pszFilename + uNameLen);
								}
							}
						}

						// Go to the next NULL character.
						while (*p++);
					} while (!bFound && *p); // end of string
				}
			}
			bSuccess = TRUE;
			UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}

	return(strFilename);
}


process_debugger_t::process_debugger_t(const char* path_to_file) :
	path_to_file_{path_to_file},
	waiting_time{ INFINITE },
	continue_debug_status{ DBG_CONTINUE }
{}


process_debugger_t::~process_debugger_t() = default;


bool process_debugger_t::start_given_process_to_debug()
{
	if (!CreateProcessA(
		this->path_to_file_.c_str(),
		NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
		NULL, NULL,
		&this->startup_info_process,
		&this->proc_info_process
	))
	{
		printf("[-] CreateProcessA error creating process '%s': 0x%X\n", this->path_to_file_.c_str(), GetLastError());
		return false;
	}

	buffer_data = (uint8_t*)malloc(file_size * sizeof(uint8_t) + 1);

	arc4.setKey((unsigned char*)key.c_str(), key.length());

	arc4.encrypt(encrypted_file, buffer_data, file_size);

	this->process_injector = process_injector_t::get_instance(buffer_data, proc_info_process.hProcess, proc_info_process.hThread);

	if (this->process_injector == nullptr)
		return false;

	return true;
}


bool process_debugger_t::start_debugging()
{
	this->process_injector->inject_into_process();

	if (ResumeThread(this->proc_info_process.hThread) == -1)
	{
		printf("ResumeThread error resuming thread with handle 0x%X: 0x%X", (unsigned int)this->proc_info_process.hThread, GetLastError());
		return false;
	}

	while (1)
	{
		if (!WaitForDebugEvent(&this->debug_event, this->waiting_time))
			return true;

		this->process_events();

		ContinueDebugEvent(
			this->debug_event.dwProcessId,
			this->debug_event.dwThreadId,
			continue_debug_status
		);
	}

}


void process_debugger_t::process_events()
{
	CREATE_PROCESS_DEBUG_INFO & create_process_info		= debug_event.u.CreateProcessInfo;
	EXIT_PROCESS_DEBUG_INFO & exit_process_info			= debug_event.u.ExitProcess;
	LOAD_DLL_DEBUG_INFO & load_dll						= debug_event.u.LoadDll;
	UNLOAD_DLL_DEBUG_INFO & unload_dll					= debug_event.u.UnloadDll;
	CREATE_THREAD_DEBUG_INFO & create_thread_info		= debug_event.u.CreateThread;
	EXIT_THREAD_DEBUG_INFO & exit_thread_info			= debug_event.u.ExitThread;
	EXCEPTION_DEBUG_INFO & exception					= debug_event.u.Exception;

	switch (this->debug_event.dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		
		printf("[EVENT] CREATE_PROCESS_DEBUG_EVENT information:\n");
		printf("\tBase Address: 0x%X\n", (unsigned int)create_process_info.lpBaseOfImage);
		printf("\tProcess Name: %s\n", GetFileNameFromHandle(create_process_info.hFile).c_str());
		break;
	case EXIT_PROCESS_DEBUG_EVENT:
		
		printf("[EVENT] EXIT_PROCESS_DEBUG_EVENT information:\n");
		printf("\tProcess ID: 0x%X\n", (unsigned int)debug_event.dwProcessId);
		printf("\tThread ID: 0x%X\n", (unsigned int)debug_event.dwThreadId);
		printf("\tExit code: 0x%X\n", (unsigned int)exit_process_info.dwExitCode);

		exit(0);

		break;
	case LOAD_DLL_DEBUG_EVENT:
		
		printf("[EVENT] LOAD_DLL_DEBUG_EVENT information:\n");
		printf("\tBase address: 0x%X\n", (unsigned int)load_dll.lpBaseOfDll);
		printf("\tDLL name: %s\n", GetFileNameFromHandle(load_dll.hFile).c_str());
		break;
	case UNLOAD_DLL_DEBUG_EVENT:
		
		printf("[EVENT] UNLOAD_DLL_DEBUG_EVENT information:\n");
		printf("\tBase address: 0x%X\n", (unsigned int)unload_dll.lpBaseOfDll);
		break;
	case CREATE_THREAD_DEBUG_EVENT:
		
		printf("[EVENT] CREATE_THREAD_DEBUG_EVENT information:\n");
		printf("\tThread handler: 0x%X\n", (unsigned int)create_thread_info.hThread);
		printf("\tProcess ID: 0x%X\n", (unsigned int)debug_event.dwProcessId);
		printf("\tThread ID: 0x%X\n", (unsigned int)debug_event.dwThreadId);
		printf("\tThread address: 0x%X\n", (unsigned int)create_thread_info.lpStartAddress);
		break;
	case EXIT_THREAD_DEBUG_EVENT:
		
		printf("[EVENT] EXIT_THREAD_DEBUG_EVENT information:\n");
		printf("\tProcess ID: 0x%X\n", (unsigned int)debug_event.dwProcessId);
		printf("\tThread ID: 0x%X\n", (unsigned int)debug_event.dwThreadId);
		printf("\tExit code: 0x%X\n", (unsigned int)exit_thread_info.dwExitCode);
		break;
	case EXCEPTION_DEBUG_EVENT:
		switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_BREAKPOINT:
			printf("[EXCEPTION] EXCEPTION_BREAKPOINT info:\n");
			printf("\tBreakpoint on address: 0x%X\n", (unsigned int)exception.ExceptionRecord.ExceptionAddress);
			if (first_breakpoint)
			{
				printf("BREAKPOINT FROM NTDLL\n");
				first_breakpoint = false;
			}
			break;
		case EXCEPTION_SINGLE_STEP:
			printf("[EXCEPTION] EXCEPTION_SINGLE_STEP info:\n");
			printf("\tSingle step on address: 0x%X\n", (unsigned int)exception.ExceptionRecord.ExceptionAddress);
			break;
		case EXCEPTION_ACCESS_VIOLATION:
			printf("[EXCEPTION] EXCEPTION_ACCESS_VIOLATION info:\n");
			printf("\tAccess violation on address: 0x%X\n", (unsigned int)exception.ExceptionRecord.ExceptionAddress);

			if ((uintptr_t)exception.ExceptionRecord.ExceptionAddress == ((uintptr_t)this->process_injector->base_address() + this->process_injector->entry_point()))
			{
				printf("Access violation executed in our code, time to replace\n");
				this->process_injector->inject_real_text_section();
				this->process_injector->set_sections_protections();

				CONTEXT context = { CONTEXT_FULL };

				GetThreadContext(this->proc_info_process.hThread, &context);

				context.Eip = ((uintptr_t)this->process_injector->base_address() + this->process_injector->entry_point());
				// Set Trap flag just for debugging
				context.EFlags |= 0x100;

				SetThreadContext(this->proc_info_process.hThread, &context);
			}

			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			printf("[EXCEPTION]\n");
			printf("\tprivilege instruction on address: 0x%X\n", (unsigned int)exception.ExceptionRecord.ExceptionAddress);

			if ((uintptr_t)exception.ExceptionRecord.ExceptionAddress == ((uintptr_t)this->process_injector->base_address() + this->process_injector->entry_point() + 3))
			{
				printf("Privileged instruction executed in our code, time to replace\n");
				this->process_injector->inject_real_text_section();
				this->process_injector->set_sections_protections();

				CONTEXT context = { CONTEXT_FULL };

				GetThreadContext(this->proc_info_process.hThread, &context);

				context.Eip = ((uintptr_t)this->process_injector->base_address() + this->process_injector->entry_point());
				// Set Trap flag just for debugging
				context.EFlags |= 0x100;

				SetThreadContext(this->proc_info_process.hThread, &context);
			}

			break;
		default:
			printf("[EXCEPTION]\n");
			printf("\tException address: 0x%X\n", (unsigned int)exception.ExceptionRecord.ExceptionAddress);
			break;
		}
	default:
		break;
	}
}