#include <Windows.h>
#include <TlHelp32.h>
typedef void(*fpfunc)(int test, char a);
typedef void(*fpfunc2)(int test2, char b, char c);
fpfunc hookfunc;
fpfunc2 hookfunc2;
void __hooked_func(int test, char a)
 {
	// body
}
void __hooked_func2(int test2, char b, char c)
{
	// body2
}
FARPROC WINAPI HookGetProcAddress(
_In_ HMODULE hModule,
_In_ LPCSTR  lpProcName
) {
if (!strcmp("func", lpProcName)) {
			return (FARPROC)((LPVOID)__hooked_func);			
}
if (!strcmp("func2", lpProcName)) {
			return (FARPROC)((LPVOID)__hooked_func2);			
}
return GetProcAddress(hModule, lpProcName);
}