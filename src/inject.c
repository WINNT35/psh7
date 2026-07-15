// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WINNT35
// inject.c - Injects psh7.dll into the running explorer.exe process.

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

static DWORD FindExplorerPid(void)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t dllPath[MAX_PATH];

    if (argc > 1)
    {
        wcsncpy(dllPath, argv[1], MAX_PATH - 1);
        dllPath[MAX_PATH - 1] = 0;
    }
    else
    {
        DWORD len = GetModuleFileNameW(NULL, dllPath, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
        {
            fwprintf(stderr, L"GetModuleFileNameW failed\n");
            return 1;
        }
        wchar_t *slash = wcsrchr(dllPath, L'\\');
        if (!slash)
        {
            fwprintf(stderr, L"unexpected path with no backslash\n");
            return 1;
        }
        wcscpy(slash + 1, L"psh7.dll");
    }

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        fwprintf(stderr, L"DLL not found: %s\n", dllPath);
        return 1;
    }

    DWORD pid = FindExplorerPid();
    if (pid == 0)
    {
        fwprintf(stderr, L"explorer.exe not found\n");
        return 1;
    }
    wprintf(L"explorer.exe PID=%lu, injecting %s\n", pid, dllPath);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc)
    {
        fwprintf(stderr, L"OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProc, NULL, pathBytes, MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath)
    {
        fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    if (!WriteProcessMemory(hProc, remotePath, dllPath, pathBytes, NULL))
    {
        fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW =
        (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW)
    {
        fwprintf(stderr, L"GetProcAddress(LoadLibraryW) failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pLoadLibraryW, remotePath, 0, NULL);
    if (!hThread)
    {
        fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    wprintf(L"LoadLibraryW returned module handle 0x%lx in remote process\n", exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);

    wprintf(L"Injection successful.\n");
    return 0;
}
