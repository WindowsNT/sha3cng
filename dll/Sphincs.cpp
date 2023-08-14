#include "pch.h"

#include "..\\sphincs\\include\\sphincs.hpp"




class SP
{
public:
	std::vector<uint8_t> p, s;
	virtual ~SP()
	{

	}
};

class BOP
{
public:

	virtual ~BOP() {};

};




NTSTATUS WINAPI SphincsGetAsymmetricEncryptionInterface(
	_In_   LPCWSTR pszProviderName,
	_In_   LPCWSTR pszAlgId,
	_Out_  BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE** ppFunctionTable,
	_In_   ULONG dwFlags
)
{
	if (!ppFunctionTable)
		return -1;
	if (_wcsicmp(pszAlgId, SPHINCS_ALGORITHM) != 0)
		return -1;
	namespace utils = sphincs_utils;


	constexpr size_t n = 16;
	constexpr uint32_t h = 63;
	constexpr uint32_t d = 7;
	constexpr uint32_t a = 12;
	constexpr uint32_t k = 14;
	constexpr size_t w = 16;
	constexpr auto v = sphincs_hashing::variant::robust;
	constexpr size_t pklen = utils::get_sphincs_pkey_len<n>();
	constexpr size_t sklen = utils::get_sphincs_skey_len<n>();
	constexpr size_t siglen = utils::get_sphincs_sig_len<n, h, d, a, k, w>();
	constexpr size_t mlen = 32;



	BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE m = {};
	*ppFunctionTable = &m;

	m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
		_In_   LPCWSTR pszAlgId,
		_In_   ULONG dwFlags
		) -> NTSTATUS
	{
		BOP* b = 0;
		b = new BOP;
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

		if (_wcsicmp(pszProperty, BCRYPT_PADDING_SCHEMES) == 0)
		{
			if (!pcbResult)
				return (NTSTATUS)-1;
			if (pbOutput == 0)
				*pcbResult = 4;
			else
			{
				DWORD r = 0;
				memcpy(pbOutput, &r, 4);
				*pcbResult = 4;
			}
			return ERROR_SUCCESS;

		}
		if (_wcsicmp(pszProperty, BCRYPT_OBJECT_LENGTH) == 0)
		{
			if (!pcbResult)
				return (NTSTATUS)-1;
			if (pbOutput == 0)
				*pcbResult = 4;
			else
			{
				DWORD r = sizeof(BOP);
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

	m.Encrypt = [](_Inout_      BCRYPT_KEY_HANDLE hKey,
		_In_         PUCHAR pbInput,
		_In_         ULONG cbInput,
		_In_opt_     VOID* pPaddingInfo,
		_Inout_opt_  PUCHAR pbIV,
		_In_         ULONG cbIV,
		_Out_opt_    PUCHAR pbOutput,
		_In_         ULONG cbOutput,
		_Out_        ULONG* pcbResult,
		_In_         ULONG dwFlags
		)
	{
		return STATUS_NOT_SUPPORTED;
	};

	m.Decrypt = [](_Inout_                                     BCRYPT_KEY_HANDLE   hKey,
		_In_reads_bytes_opt_(cbInput)                    PUCHAR   pbInput,
		_In_                                        ULONG   cbInput,
		_In_opt_                                    VOID* pPaddingInfo,
		_Inout_updates_bytes_opt_(cbIV)                    PUCHAR   pbIV,
		_In_                                        ULONG   cbIV,
		_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
		_In_                                        ULONG   cbOutput,
		_Out_                                       ULONG* pcbResult,
		_In_                                        ULONG   dwFlags
		)
	{

		return STATUS_NOT_SUPPORTED;
	};


	m.ImportKeyPair = [](_In_     BCRYPT_ALG_HANDLE hAlgorithm,
		_Inout_  BCRYPT_KEY_HANDLE hImportKey,
		_In_     LPCWSTR pszBlobType,
		_Out_    BCRYPT_KEY_HANDLE* phKey,
		_In_     PUCHAR pbInput,
		_In_     ULONG cbInput,
		_In_     ULONG dwFlags
		)
	{
		auto key = new SP();
		key->p.resize(pklen);
		key->s.resize(sklen);
		auto req = key->p.size() + key->s.size();
		if (cbInput != req)
		{
			delete key;
			return STATUS_NOT_SUPPORTED;
		}
		memcpy(key->p.data(), pbInput, key->p.size());
		memcpy(key->s.data(), pbInput + key->p.size(), key->s.size());
		*phKey = key;
		return STATUS_SUCCESS;
	};

	m.GenerateKeyPair = [](_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_    BCRYPT_KEY_HANDLE* phKey,
		_In_     ULONG dwLength,
		_In_     ULONG dwFlags
		)
	{
		auto key = new SP;
		std::vector<uint8_t> msg(mlen);

		key->s.resize(sklen);
		key->p.resize(pklen);

		sphincs::keygen<n, h, d, w, v>((uint8_t*)key->s.data(), (uint8_t*)key->p.data());

		*phKey = key;
		return STATUS_SUCCESS;
	};


	m.FinalizeKeyPair = [](_Inout_  BCRYPT_KEY_HANDLE hKey,
		_In_     ULONG dwFlags
		)
	{
		return STATUS_SUCCESS;
	};


	m.SignHash = [](_In_      BCRYPT_KEY_HANDLE hKey,
		_In_opt_  VOID* pPaddingInfo,
		_In_      PBYTE pbInput,
		_In_      DWORD cbInput,
		_Out_     PBYTE pbOutput,
		_In_      DWORD cbOutput,
		_Out_     DWORD* pcbResult,
		_In_      ULONG dwFlags
		)
	{
		SP* key = (SP*)hKey;		
		*pcbResult = siglen;
		if (!cbOutput || !pbOutput)
			return STATUS_SUCCESS;
		if (cbOutput != siglen)
			return STATUS_NOT_SUPPORTED;
		sphincs::sign<n, h, d, a, k, w, v>(pbInput, cbInput, key->s.data(), pbOutput);
		return STATUS_SUCCESS;

	};

	m.VerifySignature = [](_In_      BCRYPT_KEY_HANDLE hKey,
		_In_opt_  VOID* pPaddingInfo,
		_In_      PUCHAR pbHash,
		_In_      ULONG cbHash,
		_In_      PUCHAR pbSignature,
		_In_      ULONG cbSignature,
		_In_      ULONG dwFlags
		)
	{
		SP* key = (SP*)hKey;
		if (cbSignature != siglen)
			return STATUS_NOT_SUPPORTED;

		bool z = sphincs::verify<n, h, d, a, k, w, v>(pbHash,cbHash,pbSignature,key->p.data());
		if (z)
			return STATUS_SUCCESS;
		return STATUS_INVALID_SIGNATURE;

	};




	m.ExportKey = [](_In_   BCRYPT_KEY_HANDLE hKey,
		_In_   BCRYPT_KEY_HANDLE hExportKey,
		_In_   LPCWSTR pszBlobType,
		_Out_  PUCHAR pbOutput,
		_In_   ULONG cbOutput,
		_Out_  ULONG* pcbResult,
		_In_   ULONG dwFlags)
	{
		if (wcscmp(pszBlobType, L"") != 0)
			return STATUS_NOT_SUPPORTED;
		SP* key = (SP*)hKey;
		auto needs = key->p.size() + key->s.size();
		*pcbResult = (ULONG)needs;
		if (!pbOutput || !cbOutput)
			return STATUS_SUCCESS;
		if (cbOutput < needs)
			return STATUS_NOT_SUPPORTED;
		memcpy(pbOutput, key->p.data(), key->p.size());
		memcpy(pbOutput + key->p.size(), key->s.data(), key->s.size());
		return ERROR_SUCCESS;
	};
	m.DestroyKey = [](_Inout_  BCRYPT_KEY_HANDLE hKey
		)
	{
		if (!hKey)
			return (NTSTATUS)-1;
		SP* key = (SP*)hKey;
		delete key;
		return (NTSTATUS)STATUS_SUCCESS;
	};




	m.Version = BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE_VERSION_1;
	return ERROR_SUCCESS;
}

