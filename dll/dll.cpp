#include <windows.h>


#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x64\\bcrypt_provider.lib")
#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x64\\ncrypt_provider.lib")
#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x64\\cng_provider.lib")
#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x86\\bcrypt_provider.lib")
#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x86\\ncrypt_provider.lib")
#pragma comment (lib,"C:\\Windows Kits\\10\\Cryptographic Provider Development Kit\\Lib\\x86\\cng_provider.lib")

HINSTANCE hDLL = 0;
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpvReserved)  // reserved
{
	hDLL = hinstDLL;
	return 1;
}

