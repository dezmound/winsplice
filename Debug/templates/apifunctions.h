#include <Windows.h>
#include <TlHelp32.h>

typedef int(*fsocket)(int AF, int type, int proto);
typedef HANDLE(WINAPI * fGetProcHeap)();
typedef FARPROC(WINAPI * fGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName
	);
fGetProcHeap hookGetph;
fsocket hookSocket;
fGetProcAddress hookGetProcAddress;

HANDLE WINAPI HookGetProcessHeap() {
	return (HANDLE)0xFFAAFF;
}
int HookSocket(int AF, int type, int proto) {
	return 0xFFAAFF;
}

FARPROC WINAPI HookGetProcAddress(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName
	) { 
	if (!strcmp("socket", lpProcName)) {
		return (FARPROC)((LPVOID)HookSocket);
	}
	return hookGetProcAddress(hModule, lpProcName);
}

