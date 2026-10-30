#include "firewall.h"

#define COBJMACROS
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>


BOOL GetProcessPathByPid(DWORD pid, WCHAR* pathOut, DWORD pathSize) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed for PID %lu (Error: %lu)\n", pid, GetLastError());
        return FALSE;
    }

    MODULEENTRY32W me = { 0 };
    me.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnap, &me)) {
        wcsncpy_s(pathOut, pathSize, me.szExePath, _TRUNCATE);
        CloseHandle(hSnap);
        return TRUE;
    }

    CloseHandle(hSnap);
    return FALSE;
}


void ListRunningProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create process snapshot.\n");
        return;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    printf("\n%-8s  %s\n", "PID", "Process Name");
    printf("----------------------------------------------\n");

    if (Process32FirstW(hSnap, &pe)) {
        do {
            printf("%-8lu  %ls\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    printf("\n");
}


BOOL FirewallAddBlockRule(LPCWSTR exePath, LPCWSTR ruleName) {
    HRESULT hr = S_OK;
    INetFwPolicy2* pPolicy = NULL;
    INetFwRules* pRules = NULL;
    INetFwRule* pRule = NULL;
    BSTR bstrRuleName = NULL;
    BSTR bstrAppPath = NULL;
    BSTR bstrDescription = NULL;

    hr = CoCreateInstance(
        &CLSID_NetFwPolicy2,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2,
        (void**)&pPolicy
    );
    if (FAILED(hr)) {
        printf("[!] CoCreateInstance(NetFwPolicy2) failed: 0x%08lx\n", hr);
        return FALSE;
    }

    hr = pPolicy->lpVtbl->get_Rules(pPolicy, &pRules);
    if (FAILED(hr)) {
        printf("[!] get_Rules failed: 0x%08lx\n", hr);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    hr = CoCreateInstance(
        &CLSID_NetFwRule,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwRule,
        (void**)&pRule
    );
    if (FAILED(hr)) {
        printf("[!] CoCreateInstance(NetFwRule) failed: 0x%08lx\n", hr);
        pRules->lpVtbl->Release(pRules);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    bstrRuleName = SysAllocString(ruleName);
    bstrAppPath = SysAllocString(exePath);
    bstrDescription = SysAllocString(L"Blocked by FirewallBlock tool");

    pRule->lpVtbl->put_Name(pRule, bstrRuleName);
    pRule->lpVtbl->put_Description(pRule, bstrDescription);
    pRule->lpVtbl->put_ApplicationName(pRule, bstrAppPath);
    pRule->lpVtbl->put_Action(pRule, NET_FW_ACTION_BLOCK);
    pRule->lpVtbl->put_Direction(pRule, NET_FW_RULE_DIR_OUT);
    pRule->lpVtbl->put_Enabled(pRule, VARIANT_TRUE);
    pRule->lpVtbl->put_Profiles(pRule, NET_FW_PROFILE2_ALL);

    hr = pRules->lpVtbl->Add(pRules, pRule);
    if (FAILED(hr)) {
        printf("[!] Failed to add outbound block rule: 0x%08lx\n", hr);
    }
    else {
        printf("[+] Outbound block rule added: \"%ls\" -> %ls\n", ruleName, exePath);
    }

    // Inbound rule
    INetFwRule* pRuleIn = NULL;
    hr = CoCreateInstance(
        &CLSID_NetFwRule,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwRule,
        (void**)&pRuleIn
    );
    if (SUCCEEDED(hr)) {
        WCHAR inRuleName[512];
        _snwprintf_s(inRuleName, 512, _TRUNCATE, L"%s (Inbound)", ruleName);
        BSTR bstrInName = SysAllocString(inRuleName);

        pRuleIn->lpVtbl->put_Name(pRuleIn, bstrInName);
        pRuleIn->lpVtbl->put_Description(pRuleIn, bstrDescription);
        pRuleIn->lpVtbl->put_ApplicationName(pRuleIn, bstrAppPath);
        pRuleIn->lpVtbl->put_Action(pRuleIn, NET_FW_ACTION_BLOCK);
        pRuleIn->lpVtbl->put_Direction(pRuleIn, NET_FW_RULE_DIR_IN);
        pRuleIn->lpVtbl->put_Enabled(pRuleIn, VARIANT_TRUE);
        pRuleIn->lpVtbl->put_Profiles(pRuleIn, NET_FW_PROFILE2_ALL);

        hr = pRules->lpVtbl->Add(pRules, pRuleIn);
        if (SUCCEEDED(hr)) {
            printf("[+] Inbound block rule added: \"%ls\" -> %ls\n", inRuleName, exePath);
        }

        SysFreeString(bstrInName);
        pRuleIn->lpVtbl->Release(pRuleIn);
    }

    SysFreeString(bstrRuleName);
    SysFreeString(bstrAppPath);
    SysFreeString(bstrDescription);
    pRule->lpVtbl->Release(pRule);
    pRules->lpVtbl->Release(pRules);
    pPolicy->lpVtbl->Release(pPolicy);

    return TRUE;
}


BOOL FirewallRemoveBlockRule(LPCWSTR ruleName) {
    HRESULT hr = S_OK;
    INetFwPolicy2* pPolicy = NULL;
    INetFwRules* pRules = NULL;

    hr = CoCreateInstance(
        &CLSID_NetFwPolicy2,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2,
        (void**)&pPolicy
    );
    if (FAILED(hr)) {
        printf("[!] CoCreateInstance failed: 0x%08lx\n", hr);
        return FALSE;
    }

    hr = pPolicy->lpVtbl->get_Rules(pPolicy, &pRules);
    if (FAILED(hr)) {
        printf("[!] get_Rules failed: 0x%08lx\n", hr);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    BSTR bstrName = SysAllocString(ruleName);
    hr = pRules->lpVtbl->Remove(pRules, bstrName);
    if (FAILED(hr)) {
        printf("[!] Failed to remove rule \"%ls\": 0x%08lx\n", ruleName, hr);
    }
    else {
        printf("[+] Removed rule: \"%ls\"\n", ruleName);
    }

    // Try removing the inbound counterpart
    WCHAR inRuleName[512];
    _snwprintf_s(inRuleName, 512, _TRUNCATE, L"%s (Inbound)", ruleName);
    BSTR bstrInName = SysAllocString(inRuleName);
    hr = pRules->lpVtbl->Remove(pRules, bstrInName);
    if (SUCCEEDED(hr)) {
        printf("[+] Removed rule: \"%ls\"\n", inRuleName);
    }

    SysFreeString(bstrName);
    SysFreeString(bstrInName);
    pRules->lpVtbl->Release(pRules);
    pPolicy->lpVtbl->Release(pPolicy);

    return TRUE;
}


BOOL FirewallListBlockRules() {
    HRESULT hr = S_OK;
    INetFwPolicy2* pPolicy = NULL;
    INetFwRules* pRules = NULL;
    IUnknown* pEnum = NULL;
    IEnumVARIANT* pEnumVar = NULL;

    hr = CoCreateInstance(
        &CLSID_NetFwPolicy2,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2,
        (void**)&pPolicy
    );
    if (FAILED(hr)) {
        printf("[!] CoCreateInstance failed: 0x%08lx\n", hr);
        return FALSE;
    }

    hr = pPolicy->lpVtbl->get_Rules(pPolicy, &pRules);
    if (FAILED(hr)) {
        printf("[!] get_Rules failed: 0x%08lx\n", hr);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    hr = pRules->lpVtbl->get__NewEnum(pRules, &pEnum);
    if (FAILED(hr)) {
        printf("[!] get__NewEnum failed: 0x%08lx\n", hr);
        pRules->lpVtbl->Release(pRules);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    hr = pEnum->lpVtbl->QueryInterface(pEnum, &IID_IEnumVARIANT, (void**)&pEnumVar);
    pEnum->lpVtbl->Release(pEnum);
    if (FAILED(hr)) {
        printf("[!] QueryInterface(IEnumVARIANT) failed: 0x%08lx\n", hr);
        pRules->lpVtbl->Release(pRules);
        pPolicy->lpVtbl->Release(pPolicy);
        return FALSE;
    }

    printf("\n[*] Firewall block rules created by FirewallBlock:\n");
    printf("---------------------------------------------------\n");

    VARIANT var;
    ULONG fetched = 0;
    int count = 0;

    while (pEnumVar->lpVtbl->Next(pEnumVar, 1, &var, &fetched) == S_OK) {
        INetFwRule* pRule = NULL;
        if (var.vt == VT_DISPATCH && var.pdispVal != NULL) {
            hr = var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&pRule);
        }
        VariantClear(&var);

        if (pRule != NULL && SUCCEEDED(hr)) {
            BSTR bstrDesc = NULL;
            pRule->lpVtbl->get_Description(pRule, &bstrDesc);

            if (bstrDesc && wcscmp(bstrDesc, L"Blocked by FirewallBlock tool") == 0) {
                BSTR bstrName = NULL;
                BSTR bstrApp = NULL;
                NET_FW_RULE_DIRECTION dir;
                VARIANT_BOOL enabled;

                pRule->lpVtbl->get_Name(pRule, &bstrName);
                pRule->lpVtbl->get_ApplicationName(pRule, &bstrApp);
                pRule->lpVtbl->get_Direction(pRule, &dir);
                pRule->lpVtbl->get_Enabled(pRule, &enabled);

                printf("  [%d] Name: %ls\n", ++count, bstrName ? bstrName : L"(null)");
                printf("       App:  %ls\n", bstrApp ? bstrApp : L"(null)");
                printf("       Dir:  %s | Enabled: %s\n",
                    dir == NET_FW_RULE_DIR_OUT ? "Outbound" : "Inbound",
                    enabled == VARIANT_TRUE ? "Yes" : "No");
                printf("\n");

                SysFreeString(bstrName);
                SysFreeString(bstrApp);
            }

            SysFreeString(bstrDesc);
            pRule->lpVtbl->Release(pRule);
        }
    }

    if (count == 0) {
        printf("  (No FirewallBlock rules found)\n\n");
    }

    pEnumVar->lpVtbl->Release(pEnumVar);
    pRules->lpVtbl->Release(pRules);
    pPolicy->lpVtbl->Release(pPolicy);

    return TRUE;
}


BOOL FirewallBlockByPid(DWORD pid, LPCWSTR ruleName) {
    WCHAR exePath[MAX_PATH] = { 0 };

    if (!GetProcessPathByPid(pid, exePath, MAX_PATH)) {
        printf("[!] Could not resolve path for PID %lu\n", pid);
        return FALSE;
    }

    printf("[*] PID %lu -> %ls\n", pid, exePath);
    return FirewallAddBlockRule(exePath, ruleName);
}
