
#include "common.h"

#define SHUTDOWNPRIVILEGE_FLAG 0x1
#define DEBUGPRIVILEGE_FLAG 0x2
#define TCBPRIVILEGE_FLAG 0x4

BOOL adjust_privilege_token(LPCWSTR token_name);

int main()
{
	signed int privileges_mask;

	privileges_mask = 0;
	if (adjust_privilege_token(SE_SHUTDOWN_NAME))
		privileges_mask = SHUTDOWNPRIVILEGE_FLAG;
	if (adjust_privilege_token(SE_DEBUG_NAME))
		privileges_mask |= DEBUGPRIVILEGE_FLAG;
	if (adjust_privilege_token(SE_TCB_NAME))
		privileges_mask |= TCBPRIVILEGE_FLAG;

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