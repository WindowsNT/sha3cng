#pragma warning(disable:4005)
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt_provider.h>
#include <ncrypt_provider.h>
#include <vector>


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



#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"crypt32.lib")



#include <ntstatus.h>

#define SHA3_ALGORITHM  L"SHA3"
const wchar_t* ProviderB = L"Michael Chourdakis CNG SHA-3 Implementation";

class BOP
{
public:

};

NTSTATUS WINAPI GetHashInterface(
	_In_   LPCWSTR pszProviderName,
	_In_   LPCWSTR pszAlgId,
	_Out_  BCRYPT_HASH_FUNCTION_TABLE** ppFunctionTable,
	_In_   ULONG dwFlags
)
{
	if (!ppFunctionTable)
		return -1;
	if (pszAlgId != SHA3_ALGORITHM)
		return -1;
	BCRYPT_HASH_FUNCTION_TABLE m;
	*ppFunctionTable = &m;


	m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
		_In_   LPCWSTR pszAlgId,
		_In_   ULONG dwFlags
		) -> NTSTATUS
	{
		BOP* b = new BOP;
		*phAlgorithm = b;
		return 0;
	};
	m.CloseAlgorithmProvider = [](_Inout_ BCRYPT_ALG_HANDLE   hAlgorithm,
		_In_    ULONG   dwFlags) -> NTSTATUS
	{
		BOP* b = (BOP*)hAlgorithm;
		delete b;
		return 0;
	};

	m.GetProperty = [](_In_   BCRYPT_HANDLE hObject,
		_In_   LPCWSTR pszProperty,
		_Out_  PUCHAR pbOutput,
		_In_   ULONG cbOutput,
		_Out_  ULONG* pcbResult,
		_In_   ULONG dwFlags
		) -> NTSTATUS
	{
		return STATUS_NOT_SUPPORTED;
	};
	m.SetProperty = [](_Inout_  BCRYPT_HANDLE hObject,
		_In_     LPCWSTR pszProperty,
		_In_     PUCHAR pbInput,
		_In_     ULONG cbInput,
		_In_     ULONG dwFlags
		) ->NTSTATUS
	{
		return STATUS_NOT_SUPPORTED;
	};


	m.CreateHash = [](
		_Inout_                          BCRYPT_ALG_HANDLE   hAlgorithm,
		_Out_                           BCRYPT_HASH_HANDLE* phHash,
		_Out_writes_bytes_all_(cbHashObject) PUCHAR   pbHashObject,
		_In_                            ULONG   cbHashObject,
		_In_reads_bytes_opt_(cbSecret)       PUCHAR   pbSecret,   // optional
		_In_                            ULONG   cbSecret,   // optional
		_In_                            ULONG   dwFlags)
	{
		if (!hAlgorithm)
			return (NTSTATUS) - 1;
		BOP* b = (BOP*)hAlgorithm;

		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.Version = BCRYPT_HASH_INTERFACE_VERSION_1;
	return ERROR_SUCCESS;
}



HRESULT __stdcall DllRegisterServer()
{
	// Copy to System32
	std::vector<wchar_t> x(1000);
	std::vector<wchar_t> y(1000);
	GetModuleFileName(hDLL, x.data(), 1000);
	GetSystemDirectory(y.data(), 1000);
	wcscat_s(y.data(), 1000, L"\\cngsha3.dll");
	if (!CopyFile(x.data(), y.data(), FALSE))
		return E_FAIL;

	CRYPT_PROVIDER_REG reg = {};
	CRYPT_IMAGE_REG reg2 = {};
	reg.pUM = &reg2;
	reg.pUM->pszImage = y.data();
	CRYPT_INTERFACE_REG* rif[1] = {};
	CRYPT_INTERFACE_REG r1 = {};
	reg.pUM->rgpInterfaces = rif;
	rif[0] = &r1;
	r1.dwInterface = BCRYPT_HASH_INTERFACE;
	PWSTR u[] = { (PWSTR)SHA3_ALGORITHM };
	r1.rgpszFunctions = u;
	r1.cFunctions = 1;


	if (1)
	{
		reg.pUM->cInterfaces = 1;
		rif[0] = &r1;
		auto st = BCryptRegisterProvider(ProviderB, CRYPT_OVERWRITE, &reg);
		if (st == STATUS_OBJECT_NAME_COLLISION)
			MessageBeep(0);
		if (st != 0)
			return E_FAIL;
	}
	
	auto st = BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	return S_OK;
}

HRESULT __stdcall DllUnregisterServer()
{
	std::vector<wchar_t> y(1000);
	GetSystemDirectory(y.data(), 1000);
	wcscat_s(y.data(), 1000, L"\\cngsha3.dll");

	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_ALGORITHM, ProviderB);

	auto st = BCryptUnregisterProvider(ProviderB);
	DeleteFile(y.data());
	return S_OK;
}
