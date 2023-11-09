//This is a wrapper for DPLAYERX.DLL, it will load the original DPLAYERX.DLL -> DPLAYERY.DLL
//Allows for attaching to the F18.ICD for debugging purposes. DPLAYERY.DLL needs to be modified
//to use its new name during GetModuleHandleA lookups.

#include <Windows.h>
#include <stdio.h>

typedef void (*Detour)(unsigned char*);
HMODULE hMod = NULL;
extern "C"
{
	__declspec(dllexport) void Ox77F052CC(unsigned char* ptr)
	{
		if (hMod == 0)
		{
			printf("DPLAYERX2.DLL is not loaded\n");
			return;
		}

		FARPROC pAddr = GetProcAddress(hMod, "Ox77F052CC");
		if (pAddr == NULL)
		{
			printf("Failed to find Ox77F052CC in DPLAYERX2.DLL\n");
			return;
		}

		printf("Press any key to execute Ox77F052CC(%p) at %p\n", pAddr, ptr);
		getchar();

		((Detour)pAddr)(ptr);
		FreeLibrary(hMod);
	}
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;

	AllocConsole();
	FILE* p_file;
	freopen_s(&p_file, "CONIN$", "r", stdin);
	freopen_s(&p_file, "CONOUT$", "w", stdout);
	freopen_s(&p_file, "CONOUT$", "w", stderr);
	printf("Press any key to load DPLAYERY.DLL\n");
	getchar();
	hMod = LoadLibraryA("DPLAYERY.DLL");
	if (hMod == NULL)
	{
		printf("Failed to load DPLAYERY.DLL\n");
		return FALSE;
	}
	printf("Loaded DPLAYERY.DLL at %p\n", GetModuleHandleA("DPLAYERY.DLL"));

	return TRUE;
}
