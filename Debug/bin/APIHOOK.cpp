#include <Windows.h>
#include "apihook.h"
#include "apifunctions.h"
using namespace hook;
hook_t Hookfunc;
hook_t Hookfunc2;
hook_t HookDynamic;
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{if (dwReason == DLL_PROCESS_ATTACH)
{
InitializeHook(&Hookfunc, "module", "func", __hooked_func);
hookfunc = (fpfunc)Hookfunc.APIFunction;
InsertHook(&Hookfunc);
InitializeHook(&Hookfunc2, "module", "func2", __hooked_func2);
hookfunc2 = (fpfunc2)Hookfunc2.APIFunction;
InsertHook(&Hookfunc2);
InitializeHook(&HookDynamic, "kernel32.dll", "GetProcAddress", HookGetProcAddress);
}
else if (dwReason == DLL_PROCESS_DETACH)
{
Unhook(&Hookfunc);
FreeHook(&Hookfunc);
Unhook(&Hookfunc2);
FreeHook(&Hookfunc2);
Unhook(&HookDynamic);
FreeHook(&HookDynamic);
	}
return TRUE;
}