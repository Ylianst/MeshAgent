#define WIN32 1
#ifdef _WIN64
#define WIN64 1
#endif
#define MICROSTACK_NO_STDAFX
#define MICROSTACK_NOTLS
#include "../microstack/ILibParsers.c"
#include <assert.h>
int main(int argc, char** argv)
{
	char output[8192];
	IMAGEHLP_MODULE64 module = { 0 };
	DWORD before = SymGetOptions();
	(void)argv;
	if (argc > 1)
	{
		// The command-line address decoder can run before any chain exists.
		ILibChain_DebugOffset(output, sizeof(output), (uint64_t)&ILibCreateChain);
		assert(strstr(output, "ILibCreateChain") != NULL);
		assert(SymGetOptions() & SYMOPT_DEFERRED_LOADS);
		puts("PASS: standalone address diagnostics initialize and resolve deferred symbols");
		return 0;
	}

	SymSetOptions(before | SYMOPT_UNDNAME);
	void* chain = ILibCreateChain();
	assert(chain != NULL);
	assert((SymGetOptions() & (SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS)) ==
		(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS));
	module.SizeOfStruct = sizeof(module);
	assert(SymGetModuleInfo64(GetCurrentProcess(), (DWORD64)&ILibCreateChain, &module));
	assert(module.SymType == SymDeferred);

	// Resolve a real symbol from this executable's generated PDB on demand.
	ILibChain_DebugOffset(output, sizeof(output), (uint64_t)&ILibCreateChain);
	assert(strstr(output, "ILibCreateChain") != NULL);
	module.SizeOfStruct = sizeof(module);
	assert(SymGetModuleInfo64(GetCurrentProcess(), (DWORD64)&ILibCreateChain, &module));
	assert(module.SymType != SymDeferred && module.SymType != SymNone);
	assert(ILibCreateChain() != NULL);
	assert(ILibChain_Debug(NULL, output, sizeof(output)) != NULL);
	assert(output[0] != 0);
	puts("PASS: production chain defers symbols, preserves options, resolves on demand and walks stack");
	return 0;
}

