#pragma warning(disable:4005)
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt_provider.h>
#include <ncrypt_provider.h>
#include <vector>
#include <map>
#include <memory>


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
#pragma comment(lib,"crypt32.lib")



#include <ntstatus.h>
#include "..\\common.h"

#include "sha3.hpp"

class BOP
{
public:

	virtual bool un() = 0;

};

class HASH
{
public:

	sha3_ctx ctx;
	std::vector<unsigned char> rr;

	virtual void init() = 0;
};

class BOP256 : public BOP
{
public:

	virtual bool un() { return 1;  }

};
class BOP512 : public BOP
{
public:
	virtual bool un() { return 1; }
};

class HASH256 : public HASH
{
public:

	virtual void init()
	{
		rhash_sha3_256_init(&ctx);
		rr.resize(32);
	}
};
class HASH512 : public HASH
{
public:

	virtual void init()
	{
		rhash_sha3_512_init(&ctx);
		rr.resize(64);
	}
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
	if (wcsicmp(pszAlgId,SHA3_256_ALGORITHM) != 0 && wcsicmp(pszAlgId, SHA3_512_ALGORITHM) != 0)
		return -1;
	BCRYPT_HASH_FUNCTION_TABLE m;
	*ppFunctionTable = &m;


	m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
		_In_   LPCWSTR pszAlgId,
		_In_   ULONG dwFlags
		) -> NTSTATUS
	{
		BOP* b = 0;
		if (wcsicmp(pszAlgId,SHA3_256_ALGORITHM) == 0)
			b = new BOP256;
		if (wcsicmp(pszAlgId, SHA3_512_ALGORITHM) == 0)
			b = new BOP512;
		if (!b)
			return (NTSTATUS)-1;
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
		if (wcsicmp(pszProperty, BCRYPT_OBJECT_LENGTH) == 0)
		{
			if (!pcbResult)
				return (NTSTATUS)-1;
			if (pbOutput == 0)
				*pcbResult = 4;
			else
			{
				DWORD r = sizeof(HASH);
				if (dynamic_cast<BOP256*>((BOP*)hObject))
					r = sizeof(BOP256);
				if (dynamic_cast<BOP512*>((BOP*)hObject))
					r = sizeof(BOP512);
				if (dynamic_cast<HASH256*>((HASH*)hObject))
					r = sizeof(HASH256);
				if (dynamic_cast<HASH512*>((HASH*)hObject))
					r = sizeof(HASH512);

				memcpy(pbOutput, &r, 4);
				*pcbResult = 4;
			}
			return ERROR_SUCCESS;
		}
		if (wcsicmp(pszProperty, BCRYPT_HASH_LENGTH) == 0)
		{
			if (!pcbResult)
				return (NTSTATUS)-1;
			if (pbOutput == 0)
				*pcbResult = 4;
			else
			{
				DWORD r = 32;
				if (dynamic_cast<HASH512*>((HASH*)hObject))
					r = 64;
				memcpy(pbOutput, &r, 4);
				*pcbResult = 4;
			}
			return ERROR_SUCCESS;
		}
		if (wcsicmp(pszProperty, BCRYPT_HASH_BLOCK_LENGTH) == 0)
		{
			if (!pcbResult)
				return (NTSTATUS)-1;
			if (pbOutput == 0)
				*pcbResult = 4;
			else
			{
				DWORD r = 32;
				memcpy(pbOutput, &r, 4);
				*pcbResult = 4;
			}

			return ERROR_SUCCESS;
		}
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
		if (pbSecret)
			return (NTSTATUS)-1;
		BOP* b = (BOP*)hAlgorithm;
		HASH* ctx = 0;
		if (dynamic_cast<BOP256*>(b))
			ctx = new HASH256;
		if (dynamic_cast<BOP512*>(b))
			ctx = new HASH512;
		if (!ctx)
			return (NTSTATUS)-1;
		ctx->init();
		*phHash = (BCRYPT_HASH_HANDLE)ctx;
		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.HashData = [](_Inout_  BCRYPT_HASH_HANDLE hHash,
		_In_     PUCHAR pbInput,
		_In_     ULONG cbInput,
		_In_     ULONG dwFlags
		)
	{
		if (!hHash)
			return (NTSTATUS)-1;
		HASH* ctx = (HASH*)hHash;
		rhash_sha3_update(&ctx->ctx, pbInput, cbInput);
		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.FinishHash = [](_Inout_                     BCRYPT_HASH_HANDLE  hHash,
		_Out_writes_bytes_all_(cbOutput) PUCHAR   pbOutput,
		_In_                        ULONG   cbOutput,
		_In_                        ULONG   dwFlags)
	{
		if (!hHash || !pbOutput)
			return (NTSTATUS)-1;
		HASH* ctx = (HASH*)hHash;
		rhash_sha3_final(&ctx->ctx, ctx->rr.data());
		memcpy(pbOutput, ctx->rr.data(), cbOutput);
		ctx->init();
		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.DuplicateHash = [](_In_                            BCRYPT_HASH_HANDLE hHash,
		_Out_                           BCRYPT_HASH_HANDLE* phNewHash,
		_Out_writes_bytes_all_(cbHashObject) PUCHAR pbHashObject,
		_In_                            ULONG   cbHashObject,
		_In_                            ULONG   dwFlags)
	{
		if (!hHash)
			return (NTSTATUS)-1;
		HASH* ctx = (HASH*)hHash;
		HASH* a1 = 0;
		if (dynamic_cast<HASH256*>(ctx))
			a1 = new HASH256;
		if (dynamic_cast<HASH512*>(ctx))
			a1 = new HASH512;
		a1->ctx = ctx->ctx;
		*phNewHash = (BCRYPT_HASH_HANDLE)a1;
		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.DestroyHash = [](BCRYPT_HASH_HANDLE hHash)
	{
		if (!hHash)
			return (NTSTATUS)-1;
		HASH* ctx = (HASH*)hHash;
		delete ctx;
		return (NTSTATUS)STATUS_SUCCESS;
	};

	m.CreateMultiHash = 0;
	m.ProcessMultiOperations = 0;

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
	PWSTR u[] = { (PWSTR)SHA3_256_ALGORITHM,(PWSTR)SHA3_512_ALGORITHM};
	r1.rgpszFunctions = u;
	r1.cFunctions = 2;


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
	
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_256_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_512_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	return S_OK;
}

HRESULT __stdcall DllUnregisterServer()
{
	std::vector<wchar_t> y(1000);
	GetSystemDirectory(y.data(), 1000);
	wcscat_s(y.data(), 1000, L"\\cngsha3.dll");

	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_512_ALGORITHM, ProviderB);
	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_256_ALGORITHM, ProviderB);

	BCryptUnregisterProvider(ProviderB);
	DeleteFile(y.data());
	return S_OK;
}
