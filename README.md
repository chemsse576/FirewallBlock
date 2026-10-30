# FirewallBlock

Windows Firewall rule management tool using the COM `INetFwPolicy2` API. Programmatically block or unblock any executable's network access (inbound + outbound) from the command line.

## Features

- **Block by path** — Add inbound + outbound block rules for any executable
- **Block by PID** — Resolve a running process path and block it automatically
- **Unblock** — Remove rules by name (both directions)
- **List** — Enumerate all rules created by this tool
- **Process listing** — Show running processes with PIDs for quick targeting

## Usage

```
FirewallBlock.exe <command> [arguments]

Commands:
  block    <exe_path>  <rule_name>   Block an executable (in+out)
  blockpid <pid>       <rule_name>   Block by process PID (in+out)
  unblock  <rule_name>               Remove a block rule
  list                               List all FirewallBlock rules
  ps                                 List running processes
```

### Examples

```cmd
FirewallBlock.exe block "C:\path\to\app.exe" "Block_App"
FirewallBlock.exe blockpid 1234 "Block_PID_1234"
FirewallBlock.exe unblock "Block_App"
FirewallBlock.exe list
FirewallBlock.exe ps
```

## Build

**Developer Command Prompt (cl.exe):**
```cmd
cl.exe /nologo /W4 /Fe:FirewallBlock.exe main.c firewall.c commun.c ole32.lib oleaut32.lib advapi32.lib user32.lib
```

**CMake:**
```cmd
cmake -B build -A x64
cmake --build build --config Release
```

## Requirements

- Windows 10/11
- Administrator privileges (high integrity)
- Visual Studio Build Tools or MSVC

## Disclaimer

This tool is provided **for educational and authorized security research purposes only**.

It is intended to be used in controlled lab environments, penetration testing engagements with proper authorization, or personal system administration.

**You are solely responsible for how you use this software.** The author assumes no liability for misuse or damage caused by this tool. Do not use it on systems you do not own or do not have explicit written permission to test.

Use responsibly and in compliance with all applicable laws.
