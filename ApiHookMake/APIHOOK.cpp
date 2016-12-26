#include <Windows.h>
#include "apihook.h"
#include "apifunctions.h"
using namespace hook;
hook_t HookBCryptEncrypt;
hook_t HookGetProcessHeap;
hook_t HookDynamic;
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{if (dwReason == DLL_PROCESS_ATTACH)
{
InitializeHook(&HookBCryptEncrypt, "bcrypt.dll", "BCryptEncrypt", __hooked_BCryptEncrypt);
hookBCryptEncrypt = (fpBCryptEncrypt)HookBCryptEncrypt.APIFunction;
InsertHook(&HookBCryptEncrypt);
InitializeHook(&HookGetProcessHeap, "kernel32.dll", "GetProcessHeap", __hooked_GetProcessHeap);
hookGetProcessHeap = (fpGetProcessHeap)HookGetProcessHeap.APIFunction;
InsertHook(&HookGetProcessHeap);
InitializeHook(&HookDynamic, "kernel32.dll", "GetProcAddress", HookGetProcAddress);
hookGetProcAddress = (fGetProcAddress)HookDynamic.APIFunction;InsertHook(&HookDynamic);}
else if (dwReason == DLL_PROCESS_DETACH)
{
Unhook(&HookBCryptEncrypt);
FreeHook(&HookBCryptEncrypt);
Unhook(&HookGetProcessHeap);
FreeHook(&HookGetProcessHeap);
Unhook(&HookDynamic);
FreeHook(&HookDynamic);
	}
return TRUE;
}