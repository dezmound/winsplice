#include <Windows.h>
#include "apihook.h"
#include "apifunctions.h"

using namespace hook;
hook_t Hook;
hook_t HookDynamic;

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		InitializeHook(&Hook, "ws2_32.dll", "socket", HookSocket);
		InitializeHook(&HookDynamic, "kernel32.dll", "GetProcAddress", HookGetProcAddress);
		hookSocket = (fsocket)Hook.APIFunction;
		hookGetProcAddress = (fGetProcAddress)HookDynamic.APIFunction;
		InsertHook(&Hook);
		InsertHook(&HookDynamic);
	}
	else if (dwReason == DLL_PROCESS_DETACH) 
	{
		Unhook(&Hook);
		FreeHook(&Hook);
		Unhook(&HookDynamic);
		FreeHook(&HookDynamic);
	}
	return TRUE;
}