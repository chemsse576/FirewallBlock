#pragma once

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <netfw.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <time.h>

BOOL IsProcessHighIntegrity();
BOOL SetDebugPrivilege();
