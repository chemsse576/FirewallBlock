#pragma once

#include "commun.h"
#include <objbase.h>

BOOL FirewallAddBlockRule(LPCWSTR exePath, LPCWSTR ruleName);
BOOL FirewallRemoveBlockRule(LPCWSTR ruleName);
BOOL FirewallListBlockRules();
BOOL FirewallBlockByPid(DWORD pid, LPCWSTR ruleName);
BOOL GetProcessPathByPid(DWORD pid, WCHAR* pathOut, DWORD pathSize);
void ListRunningProcesses();
