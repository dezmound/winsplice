#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
typedef FARPROC(WINAPI * fGetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR  lpProcName);
 typedef NTSTATUS(WINAPI *fpBCryptEncrypt)(
	_Inout_     BCRYPT_KEY_HANDLE hKey,
	_In_        PUCHAR            pbInput,
	_In_        ULONG             cbInput,
	_In_opt_    VOID              *pPaddingInfo,
	_Inout_opt_ PUCHAR            pbIV,
	_In_        ULONG             cbIV,
	_Out_opt_   PUCHAR            pbOutput,
	_In_        ULONG             cbOutput,
	_Out_       ULONG             *pcbResult,
	_In_        ULONG             dwFlags
	);
typedef HANDLE(WINAPI *fpGetProcessHeap)();
fGetProcAddress hookGetProcAddress;
fpBCryptEncrypt hookBCryptEncrypt;
fpGetProcessHeap hookGetProcessHeap;
NTSTATUS WINAPI __hooked_BCryptEncrypt(
	_Inout_     BCRYPT_KEY_HANDLE hKey,
	_In_        PUCHAR            pbInput,
	_In_        ULONG             cbInput,
	_In_opt_    VOID              *pPaddingInfo,
	_Inout_opt_ PUCHAR            pbIV,
	_In_        ULONG             cbIV,
	_Out_opt_   PUCHAR            pbOutput,
	_In_        ULONG             cbOutput,
	_Out_       ULONG             *pcbResult,
	_In_        ULONG             dwFlags
	)

{
	printf("Hooked encrypt!\n");
	if (pbOutput != NULL){
		FILE * decFile = fopen("hookedBear.jpg", "wb");
		printf("Length of buffer: %d\n", cbInput);
		printf("Wrote %d bytes\n", fwrite(pbInput, 1, cbInput, decFile));
		fclose(decFile);
	}
	return hookBCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}
HANDLE WINAPI __hooked_GetProcessHeap()
 {
	printf("Hooked! 0x%X\n", hookGetProcessHeap);
	return hookGetProcessHeap();
}
FARPROC WINAPI HookGetProcAddress(
_In_ HMODULE hModule,
_In_ LPCSTR  lpProcName
) {
if (!strcmp("BCryptEncrypt", lpProcName)) {
			return (FARPROC)((LPVOID)__hooked_BCryptEncrypt);			
}
if (!strcmp("GetProcessHeap", lpProcName)) {
			return (FARPROC)((LPVOID)__hooked_GetProcessHeap);			
}
return GetProcAddress(hModule, lpProcName);
}