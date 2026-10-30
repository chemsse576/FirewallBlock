@echo off
echo [*] Building FirewallBlock...
echo.

cl.exe /nologo /W4 /Fe:FirewallBlock.exe main.c firewall.c commun.c ole32.lib oleaut32.lib advapi32.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build successful: FirewallBlock.exe
) else (
    echo.
    echo [!] Build failed.
)
