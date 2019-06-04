#pragma once

#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

typedef struct _RELOC_RECORD
{
	WORD offset : 12;
	WORD type : 4;
} RELOC_RECORD;

#endif // !COMMON_H
