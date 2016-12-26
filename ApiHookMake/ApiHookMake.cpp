#include "stdafx.h"
#define __MAKE_DIR L"."
#define __APIFUNCTIONS_FILE L"/apifunctions.h"
#define __APIBODY_FILE L"/APIHOOK.cpp"
#define __COMPILE_PARAMS L""
#define __PATH_TO_CL L"\".\\bin\\cl.exe\" /LD APIHOOK.CPP"
#define __PATH_TO_VCVARSBAT L"vcvarsall.bat & "
#define __INJECTOR L"InjectDll.exe "
#define __ADD_LIBS_FILE L"addLibs.h"
#define __STRCON(x,y) memset(__strconbuffer, 0, 1024 * sizeof(WCHAR));\
	lstrcpy(__strconbuffer, x); \
	lstrcat(__strconbuffer, y);
FILE *iHeaderTemplate, *iBodyTemplate, *iFunctionsFile, *addLibsFile;
typedef struct {
	string* returns;
	string* params;
	string* prefics;
	string* name;
	string* lib;
	string* body;
} Function;
WCHAR __strconbuffer[1024];
Function** functions;
long get_functions_count(){ return 0; };
vector<string> split(const string& str, const string& delim)
{
	vector<string> tokens;
	size_t prev = 0, pos = 0;
	do
	{
		pos = str.find(delim, prev);
		if (pos == string::npos) pos = str.length();
		string token = str.substr(prev, pos - prev);
		if (!token.empty()) tokens.push_back(token);
		prev = pos + delim.length();
	} while (pos < str.length() && prev < str.length());
	return tokens;
}

Function** getFunctions(FILE* iFunctionsFile, PDWORD count){
	CHAR lastBreacket = 0, readedSymb;
	INT functionsCount = 0;
	Function** functions = NULL;
	CHAR buffer[1024];
	INT index = 0;
	//Count of functions in template file
	while (!feof(iFunctionsFile)){
		if ((readedSymb = fgetc(iFunctionsFile)) == '{') {
			lastBreacket++;
		} else if (readedSymb == '}') {
			if (--lastBreacket == 0) {
				functionsCount++;
			}
		}
	}
	if (functionsCount == 0)
		return NULL;
	fseek(iFunctionsFile, SEEK_SET, 0);
	functions = new Function*[functionsCount];
	while (!feof(iFunctionsFile)) {
		int res = 0;
		if ((res = fscanf(iFunctionsFile, "%s", buffer)) < 0)
			break;
		string* returns = new string(buffer);
		fscanf(iFunctionsFile, "%[ ]*", buffer);
		fscanf(iFunctionsFile, "%[^(]", buffer);
		string absolueName(buffer);
		string* prefics = NULL;
		vector<string> splitedHeader = split(absolueName, string(" "));
		if (splitedHeader.size() == 2){
			prefics = new string(splitedHeader[0]);
			absolueName = string(buffer + prefics->size() + 1);
		}
		vector<string> splitedName = split(absolueName, string("->"));
		fscanf(iFunctionsFile, "%[^)]", buffer);
		string* params = new string(string(buffer) + string(")"));
		fscanf(iFunctionsFile, ")", buffer);
		fscanf(iFunctionsFile, "%[^@]", buffer);
		string* body = new string(buffer);
		fscanf(iFunctionsFile, "@", buffer);
		Function* function = new Function();
		function->prefics = prefics;
		function->body = body;
		function->lib = new string(splitedName[0]);
		function->name = new string(splitedName[1]);
		function->params = params;
		function->returns = returns;
		functions[index++] = function;
	}
	if (count != NULL){
		*count = functionsCount;
	}
	return functions;
}
void freeFunctions(Function** functions, DWORD functionsCount){
	for (DWORD i = 0; i < functionsCount; i++){
		delete functions[i]->body;
		delete functions[i]->name;
		delete functions[i]->lib;
		delete functions[i]->params;
		delete functions[i]->returns;
	}
}
void makeHeader(FILE* iHeaderTemplate, Function** functions, DWORD functionsCount){
	fputs("#include <Windows.h>\n\r#include <TlHelp32.h>\n\rtypedef FARPROC(WINAPI * fGetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR  lpProcName);\n\r ", iHeaderTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iHeaderTemplate, "typedef %s(%s *fp%s)%s;\n\r", 
			functions[i]->returns->c_str(),
			functions[i]->prefics ? functions[i]->prefics->c_str() : "",
			functions[i]->name->c_str(),
			functions[i]->params->c_str()
			);
	}
	fputs("fGetProcAddress hookGetProcAddress;\r\n", iHeaderTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iHeaderTemplate, "fp%s hook%s;\n\r", 
			functions[i]->name->c_str(),
			functions[i]->name->c_str()
			);
	}
	fputs("", iHeaderTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iHeaderTemplate, "%s %s __hooked_%s%s\n\r%s\n\r",
			functions[i]->returns->c_str(),
			functions[i]->prefics ? functions[i]->prefics->c_str() : "",
			functions[i]->name->c_str(),
			functions[i]->params->c_str(),
			functions[i]->body->c_str()
			);
	}
	fputs("FARPROC WINAPI HookGetProcAddress(\n\r_In_ HMODULE hModule,\n\r_In_ LPCSTR  lpProcName\n\r) {\n\r", iHeaderTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iHeaderTemplate, "if (!strcmp(\"%s\", lpProcName)) {\n\r\
			return (FARPROC)((LPVOID)__hooked_%s);\
			\n\r}\n\r",
			functions[i]->name->c_str(), 
			functions[i]->name->c_str()
			);
	}
	fputs("return GetProcAddress(hModule, lpProcName);\n\r}", iHeaderTemplate);
}
void makeBody(FILE* iBodyTemplate, Function** functions, DWORD functionsCount){
	fputs("#include <Windows.h>\n\r#include \"apihook.h\"\n\r#include \"apifunctions.h\"\n\rusing namespace hook;\n\r", iBodyTemplate);
	fputs("", iBodyTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iBodyTemplate, "hook_t Hook%s;\n\r",
			functions[i]->name->c_str()
			);
	}
	fputs("hook_t HookDynamic;\n\r", iBodyTemplate);
	fputs("", iBodyTemplate);
	fputs("BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)\n\r\{if (dwReason == DLL_PROCESS_ATTACH)\n\r{\n\r", iBodyTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iBodyTemplate, "InitializeHook(&Hook%s, \"%s\", \"%s\", __hooked_%s);\n\rhook%s = (fp%s)Hook%s.APIFunction;\n\rInsertHook(&Hook%s);\n\r",
			functions[i]->name->c_str(),
			functions[i]->lib->c_str(),
			functions[i]->name->c_str(),
			functions[i]->name->c_str(),
			functions[i]->name->c_str(),
			functions[i]->name->c_str(),
			functions[i]->name->c_str(),
			functions[i]->name->c_str()
			);
	}
	fputs("InitializeHook(&HookDynamic, \"kernel32.dll\", \"GetProcAddress\", HookGetProcAddress);\n\rhookGetProcAddress = (fGetProcAddress)HookDynamic.APIFunction;InsertHook(&HookDynamic);", iBodyTemplate);
	fputs("}\n\relse if (dwReason == DLL_PROCESS_DETACH)\n\r{\n\r", iBodyTemplate);
	for (DWORD i = 0; i < functionsCount; i++){
		fprintf(iBodyTemplate, "Unhook(&Hook%s);\n\rFreeHook(&Hook%s);\n\r",
			functions[i]->name->c_str(),
			functions[i]->name->c_str()
			);
	}
	fputs("Unhook(&HookDynamic);\n\rFreeHook(&HookDynamic);\n\r", iBodyTemplate);
	fputs("	}\n\rreturn TRUE;\n\r}", iBodyTemplate);
}
void compile(WCHAR** argv){
	CHAR addLibsBuffer[2056];
	memset(addLibsBuffer, 0, 2056 * sizeof(CHAR));
	DWORD functionsCount = 0;
	__STRCON(__MAKE_DIR, __APIFUNCTIONS_FILE);
	iHeaderTemplate = _wfopen(__strconbuffer, L"w");
	__STRCON(__MAKE_DIR, __APIBODY_FILE);
	iBodyTemplate = _wfopen(__strconbuffer, L"w");
	iFunctionsFile = _wfopen(argv[2], L"r");
	addLibsFile = _wfopen(__ADD_LIBS_FILE, L"r");
	DWORD readed = fread(addLibsBuffer, sizeof(CHAR), 2056, addLibsFile);
	fwrite(addLibsBuffer, sizeof(CHAR), readed, iHeaderTemplate);
	functions = getFunctions(iFunctionsFile, &functionsCount);
	makeHeader(iHeaderTemplate, functions, functionsCount);
	makeBody(iBodyTemplate, functions, functionsCount);
	fcloseall();
	__STRCON(__PATH_TO_VCVARSBAT, __PATH_TO_CL);
	_wsystem(L"echo %cd%");
	_wsystem(__PATH_TO_VCVARSBAT);
	_wsystem(__strconbuffer);
	_wsystem(L"pause");
	freeFunctions(functions, functionsCount);
}
void inject(WCHAR** argv, DWORD argc){
	WCHAR cmd[128];
	if (argc > 3){
		if (argc > 4){
			wsprintf(cmd, L"InjectDll.exe %s %s --shadow \"%s\"", argv[3], argv[4], argv[5]);
		} else {
			wsprintf(cmd, L"InjectDll.exe %s %s", argv[3], argv[4]);
		}
		STARTUPINFO suInfo = { sizeof(suInfo) };
		PROCESS_INFORMATION procInfo;
		bool success = CreateProcessW(__INJECTOR,
			cmd,
			NULL,
			NULL,
			FALSE,
			THREAD_PRIORITY_NORMAL,
			NULL,
			NULL,
			&suInfo,
			&procInfo);
		WaitForSingleObject(procInfo.hProcess, INFINITE);
		system("pause");
	} else {
		if (argc > 3){
			wsprintf(cmd, L"%s %s --shadow", argv[1], argv[2]);
		} else{
			wsprintf(cmd, L"%s %s", argv[1], argv[2]);
		}
		__STRCON(__INJECTOR, cmd);
		_wsystem(__strconbuffer);
		system("pause");
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	if (argc > 2) {
		if (!lstrcmpW(argv[1], L"-c")) {
			compile(argv);
		} else if (!lstrcmpW(argv[1], L"-ci")) {
			compile(argv);
			inject(argv, argc);
		} else if (!lstrcmpW(argv[1], L"-i")) {
			inject(argv, argc);
		}
	}
	return 0;
}
