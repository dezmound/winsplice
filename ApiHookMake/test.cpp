NTSTATUS WINAPI bcrypt.dll->BCryptEncrypt(
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
}@

HANDLE WINAPI kernel32.dll->GetProcessHeap() {
	printf("Hooked! 0x%X\n", hookGetProcessHeap);
	return hookGetProcessHeap();
}