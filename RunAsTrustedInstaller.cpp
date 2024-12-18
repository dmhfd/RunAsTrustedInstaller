#include <windows.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <AclApi.h>
#include <WtsApi32.h>
#include <WinUser.h>
#include <winternl.h>
#include <wincodec.h>
#include <PropIdl.h>
#include "privilege.h"
EXTERN_C NTSYSAPI ULONG NTAPI CsrGetProcessId();
void PrintLastError(DWORD error = -114514)
{
    DWORD errorCode = error == -114514 ? GetLastError() : error;

    LPSTR errorMessage = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD languageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

    if (FormatMessageA(flags, NULL, errorCode, languageId, (LPSTR)&errorMessage, 0, NULL) != 0)
    {
        printf("Error: %lu %s\n", errorCode, errorMessage);
        LocalFree(errorMessage);
    }
    else
    {
        printf("Failed to retrieve error message. Error code: %lu\n", errorCode);
    }
}
HANDLE getSysToken()
{
    HANDLE hToken, hProcess;
    DWORD pid = CsrGetProcessId();
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if (!hProcess)
    {
        PrintLastError();
        MessageBoxW(0, L"OpenProcess csrss", 0, 0);
        return 0;
    }
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
    {
        PrintLastError();
        MessageBoxW(0, L"OpenProcessToken csrss", 0, 0);
        return 0;
    }
    HANDLE hDuplicateToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken))
    {
        PrintLastError();
        MessageBoxW(0, L"DuplicateTokenEx csrss", 0, 0);
        return 0;
    }
    return hDuplicateToken;
}
int main()
{
    wchar_t *cmdline = GetCommandLineW();
    int argc;
    LPWSTR *argv = CommandLineToArgvW(cmdline, &argc);
    BOOLEAN e;
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &e);
    SC_HANDLE hScm, hSvc;
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm)
    {
        PrintLastError();
        MessageBoxW(0, L"OpenSCManager", 0, 0);
        return 0;
    }
    hSvc = OpenServiceW(hScm, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc)
    {
        PrintLastError();
        MessageBoxW(0, L"OpenServiceW", 0, 0);
        return 0;
    }
    if (!StartServiceW(hSvc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err != 1056)
        {
            PrintLastError(err);
            MessageBoxW(0, L"StartServiceW", 0, 0);
            return 0;
        }
    }
    HANDLE hToken, hProcess;
    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    while (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
    {
        PrintLastError();
        Sleep(100);
    }
    DWORD pid = serviceStatus.dwProcessId;
    HANDLE sysToken = getSysToken();
    if (!ImpersonateLoggedOnUser(sysToken))
    {
        PrintLastError();
        MessageBoxW(0, L"ImpersonateLoggedOnUser", 0, 0);
        return 0;
    }
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &e);
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if (!hProcess)
    {
        PrintLastError();
        MessageBoxW(0, L"OpenProcess TrustedInstaller", 0, 0);
        return 0;
    }
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
    {
        PrintLastError();
        MessageBoxW(0, L"OpenProcessToken TrustedInstaller", 0, 0);
        return 0;
    }
    HANDLE hDuplicateToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken))
    {
        PrintLastError();
        MessageBoxW(0, L"DuplicateTokenEx TrustedInstaller", 0, 0);
        return 0;
    }
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
    if (!CreateProcessWithTokenW(hDuplicateToken, 0, argc < 2 ? L"C:\\Windows\\system32\\cmd.exe" : argv[1], 0, 0, NULL, NULL, &si, &pi))
    {
        PrintLastError();
        MessageBoxW(0, L"CreateProcessWithTokenW", 0, 0);
        return 0;
    }
    return 0;
}