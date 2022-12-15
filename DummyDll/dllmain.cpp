// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    DWORD dwCurrentPid = GetCurrentProcessId();

    std::string hello = "Hello from dllmain from PID " + std::to_string(dwCurrentPid);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, hello.c_str(), "d00t", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}