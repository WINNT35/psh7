// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WINNT35
// psh7.c - forces Explorer column headers visible in all view modes

#include <windows.h>
#include <shobjidl.h>
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include "../minhook/include/MinHook.h"

// Logging is compiled in only with -DPSH7_DEBUG (see build.sh)
#ifdef PSH7_DEBUG
static void Log(const wchar_t *fmt, ...);
#else
#define Log(...) ((void)0)
#endif

typedef struct
{
    const BYTE *bytes;
    const BOOL *isWildcard;
    int len;
    const wchar_t *name;
} Signature;

// Byte signature for UIViewHeader::_ViewRequestsHeaders in ExplorerFrame.dll;
// no wildcards needed; no relocatable bytes in this span (vtable call is fixed [rax+0x40])
static const BYTE s_viewRequestsHeadersBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x02, 0x48, 0x8B,
    0xFA, 0x48, 0x8D, 0x54, 0x24, 0x38, 0x48, 0x8B, 0xCF, 0xBB, 0x01, 0x00, 0x00, 0x00, 0xFF,
    0x50, 0x40, 0x85, 0xC0, 0x78, 0x2A, 0x48, 0x8B, 0x07, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x48,
    0x8B, 0xCF, 0xFF,
};
static const BOOL s_viewRequestsHeadersWildcard[sizeof(s_viewRequestsHeadersBytes)] = { 0 };
static const Signature s_viewRequestsHeadersSig = {
    s_viewRequestsHeadersBytes, s_viewRequestsHeadersWildcard,
    sizeof(s_viewRequestsHeadersBytes), L"UIViewHeader::_ViewRequestsHeaders"
};

// Scans executable sections of hModule for sig; aborts if signature does not match exactly once
static void *ScanForPattern(HMODULE hModule, const Signature *sig)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dos->e_lfanew);

    BYTE *base = (BYTE *)hModule;
    void *found = NULL;
    int matchCount = 0;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++)
    {
        if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        DWORD sectionStart = sections[s].VirtualAddress;
        DWORD sectionEnd = sectionStart + sections[s].Misc.VirtualSize;

        for (DWORD rva = sectionStart; rva + (DWORD)sig->len <= sectionEnd; rva++)
        {
            BOOL ok = TRUE;
            for (int i = 0; i < sig->len; i++)
            {
                if (!sig->isWildcard[i] && base[rva + i] != sig->bytes[i])
                {
                    ok = FALSE;
                    break;
                }
            }
            if (ok)
            {
                Log(L"  [%s] match at rva=0x%08lx", sig->name, rva);
                matchCount++;
                found = base + rva;
            }
        }
    }

    Log(L"[%s] matchCount=%d", sig->name, matchCount);
    return (matchCount == 1) ? found : NULL;
}

#ifdef PSH7_DEBUG
static void Log(const wchar_t *fmt, ...)
{
    wchar_t buf[256];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf(buf, 255, fmt, args);
    va_end(args);
    buf[255] = 0;

    wchar_t line[320];
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snwprintf(line, 319, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [psh7] %s\r\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
    line[319] = 0;

    wchar_t path[MAX_PATH];
    DWORD tempLen = GetTempPathW(MAX_PATH, path);
    if (tempLen == 0 || tempLen >= MAX_PATH)
        return;
    if (wcscat_s(path, MAX_PATH, L"psh7.log") != 0)
        return;

    HANDLE hFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    char utf8[640];
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), NULL, NULL);
    if (utf8Len > 1)
    {
        DWORD written = 0;
        WriteFile(hFile, utf8, utf8Len - 1, &written, NULL);
    }
    CloseHandle(hFile);
}
#endif

// Scans for sig and installs a MinHook detour; aborts if unsafe 
static void ScanAndHook(HMODULE hModule, const Signature *sig, void *detour, void **outOrig)
{
    void *target = ScanForPattern(hModule, sig);
    if (!target)
    {
        Log(L"[%s] signature scan found zero or multiple matches, aborting this hook", sig->name);
        return;
    }
    Log(L"[%s] signature scan matched exactly once, target=0x%p", sig->name, target);

    MH_STATUS mhStatus = MH_CreateHook(target, detour, outOrig);
    if (mhStatus != MH_OK)
    {
        Log(L"[%s] MH_CreateHook failed: %d", sig->name, mhStatus);
        return;
    }

    mhStatus = MH_EnableHook(target);
    if (mhStatus != MH_OK)
    {
        Log(L"[%s] MH_EnableHook failed: %d", sig->name, mhStatus);
        return;
    }

    Log(L"[%s] hook installed successfully", sig->name);
}

static void *g_origViewRequestsHeaders = NULL;

// Always return 1 (show headers) regardless of folder flags or view mode
static int Hook_ViewRequestsHeaders(void *pThis, void *pViewSettings)
{
    (void)pThis;
    (void)pViewSettings;
    return 1;
}

static BOOL IsHostExplorer(void)
{
    WCHAR path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return FALSE;

    WCHAR *fileName = path;
    for (WCHAR *p = path; *p; ++p)
    {
        if (*p == L'\\' || *p == L'/')
            fileName = p + 1;
    }
    return _wcsicmp(fileName, L"explorer.exe") == 0;
}

static DWORD WINAPI InstallHookThread(LPVOID unused)
{
    (void)unused;

    Log(L"InstallHookThread started");

    MH_STATUS mhStatus = MH_Initialize();
    if (mhStatus != MH_OK)
    {
        Log(L"MH_Initialize failed: %d", mhStatus);
        return 0;
    }

    HMODULE hExplorerFrame = GetModuleHandleW(L"ExplorerFrame.dll");
    if (!hExplorerFrame)
    {
        Log(L"ExplorerFrame.dll not found in process, aborting");
        return 0;
    }

    Log(L"ExplorerFrame.dll base=0x%p", (void *)hExplorerFrame);
    ScanAndHook(hExplorerFrame, &s_viewRequestsHeadersSig, &Hook_ViewRequestsHeaders, (void **)&g_origViewRequestsHeaders);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        if (!IsHostExplorer())
            break;
        Log(L"loaded into explorer.exe, spawning install thread");
        // Hook installation runs on a new thread to avoid holding the loader lock in DllMain
        CloseHandle(CreateThread(NULL, 0, InstallHookThread, NULL, 0, NULL));
        break;

    case DLL_PROCESS_DETACH:
        if (g_origViewRequestsHeaders)
        {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
        break;
    }
    return TRUE;
}