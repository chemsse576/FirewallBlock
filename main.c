#include "firewall.h"


void PrintBanner() {
    printf("\n");
    printf("  ============================================\n");
    printf("       FirewallBlock - Windows Firewall Tool\n");
    printf("  ============================================\n\n");
}


void PrintUsage() {
    printf("  Usage:\n");
    printf("    FirewallBlock.exe <command> [arguments]\n\n");
    printf("  Commands:\n");
    printf("    block   <exe_path>  <rule_name>   Block an executable (in+out)\n");
    printf("    blockpid <pid>      <rule_name>   Block by process PID (in+out)\n");
    printf("    unblock <rule_name>               Remove a block rule\n");
    printf("    list                              List all FirewallBlock rules\n");
    printf("    ps                                List running processes\n\n");
    printf("  Examples:\n");
    printf("    FirewallBlock.exe block \"C:\\malware.exe\" \"Block_Malware\"\n");
    printf("    FirewallBlock.exe blockpid 1234 \"Block_PID_1234\"\n");
    printf("    FirewallBlock.exe unblock \"Block_Malware\"\n");
    printf("    FirewallBlock.exe list\n");
    printf("    FirewallBlock.exe ps\n\n");
}


int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();

    if (!IsProcessHighIntegrity()) {
        printf("[!] This tool requires administrator privileges.\n");
        printf("[!] Please run as Administrator.\n");
        return 1;
    }

    printf("[+] Running with high integrity.\n");

    if (!SetDebugPrivilege()) {
        printf("[!] Warning: Could not enable SeDebugPrivilege.\n");
    }
    else {
        printf("[+] SeDebugPrivilege enabled.\n");
    }

    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        printf("[!] CoInitializeEx failed: 0x%08lx\n", hr);
        return 1;
    }

    BOOL result = FALSE;

    if (_wcsicmp(argv[1], L"block") == 0) {
        if (argc < 4) {
            printf("[!] Usage: block <exe_path> <rule_name>\n");
        }
        else {
            result = FirewallAddBlockRule(argv[2], argv[3]);
        }
    }
    else if (_wcsicmp(argv[1], L"blockpid") == 0) {
        if (argc < 4) {
            printf("[!] Usage: blockpid <pid> <rule_name>\n");
        }
        else {
            DWORD pid = (DWORD)_wtoi(argv[2]);
            result = FirewallBlockByPid(pid, argv[3]);
        }
    }
    else if (_wcsicmp(argv[1], L"unblock") == 0) {
        if (argc < 3) {
            printf("[!] Usage: unblock <rule_name>\n");
        }
        else {
            result = FirewallRemoveBlockRule(argv[2]);
        }
    }
    else if (_wcsicmp(argv[1], L"list") == 0) {
        result = FirewallListBlockRules();
    }
    else if (_wcsicmp(argv[1], L"ps") == 0) {
        ListRunningProcesses();
        result = TRUE;
    }
    else {
        printf("[!] Unknown command: %ls\n\n", argv[1]);
        PrintUsage();
    }

    CoUninitialize();

    return result ? 0 : 1;
}
