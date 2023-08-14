#include "pch.h"

#include "..\\dilithium\\include\\prng.hpp"
#include "..\\dilithium\\include\\dilithium.hpp"
#include "..\\dilithium\\include\\dilithium2.hpp"
#include "..\\dilithium\\include\\dilithium3.hpp"
#include "..\\dilithium\\include\\dilithium5.hpp"


namespace DILITHIUM_ALGO
{

	class PKA
	{
	public:
		virtual void nu() {}
		virtual ~PKA()
		{

		}
	};

	class DIL : public PKA
	{
	public:
		int t = 0;
		std::vector<uint8_t> p, s;
		DIL(int ty = 2)
		{
			t = ty;
		}

		virtual ~DIL()
		{

		}
	};

	class BOP
	{
	public:

		virtual bool un() = 0;

	};

	class DIL2 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};
	class DIL3 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};
	class DIL5 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};

}

NTSTATUS WINAPI DilithiumGetAsymmetricEncryptionInterface(
	_In_   LPCWSTR pszProviderName,
	_In_   LPCWSTR pszAlgId,
	_Out_  BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE** ppFunctionTable,
	_In_   ULONG dwFlags
)
{
	using namespace DILITHIUM_ALGO;
	if (!ppFunctionTable)
		return -1;
	if (_wcsicmp(pszAlgId, DILITHIUM_2_ALGORITHM) != 0 && _wcsicmp(pszAlgId, DILITHIUM_3_ALGORITHM) != 0 && _wcsicmp(pszAlgId, DILITHIUM_5_ALGORITHM) != 0)
		return -1;

	BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE m = {};
	*ppFunctionTable = &m;

	m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
		_In_   LPCWSTR pszAlgId,
		_In_   ULONG dwFlags
		) -> NTSTATUS
	{
		BOP* b = 0;
		if (_wcsicmp(pszAlgId, DILITHIUM_2_ALGORITHM) == 0)
			b = new DIL2;
		if (_wcsicmp(pszAlgId, DILITHIUM_3_ALGORITHM) == 0)
			b = new DIL3;
		if (_wcsicmp(pszAlgId, DILITHIUM_5_ALGORITHM) == 0)
			b = new DIL5;
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
				if (dynamic_cast<DIL2*>((BOP*)hObject))
					r = sizeof(DIL2);
				if (dynamic_cast<DIL3*>((BOP*)hObject))
					r = sizeof(DIL3);
				if (dynamic_cast<DIL5*>((BOP*)hObject))
					r = sizeof(DIL5);

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
		BOP* k = (BOP*)hAlgorithm;
		if (dynamic_cast<DIL2*>(k))
		{
			auto k = new DIL(2);
			k->p.resize(dilithium2::PubKeyLen);
			k->s.resize(dilithium2::SecKeyLen);
			auto req = k->p.size() + k->s.size();
			if (cbInput != req)
			{
				delete k;
				return STATUS_NOT_SUPPORTED;
			}
			memcpy(k->p.data(), pbInput, k->p.size());
			memcpy(k->s.data(), pbInput + k->p.size(), k->s.size());
			*phKey = k;
			return STATUS_SUCCESS;
		}
		if (dynamic_cast<DIL3*>(k))
		{
			auto k = new DIL(3);
			k->p.resize(dilithium3::PubKeyLen);
			k->s.resize(dilithium3::SecKeyLen);
			auto req = k->p.size() + k->s.size();
			if (cbInput != req)
			{
				delete k;
				return STATUS_NOT_SUPPORTED;
			}
			memcpy(k->p.data(), pbInput, k->p.size());
			memcpy(k->s.data(), pbInput + k->p.size(), k->s.size());
			*phKey = k;
			return STATUS_SUCCESS;
		}
		if (dynamic_cast<DIL5*>(k))
		{
			auto k = new DIL(5);
			k->p.resize(dilithium5::PubKeyLen);
			k->s.resize(dilithium5::SecKeyLen);
			auto req = k->p.size() + k->s.size();
			if (cbInput != req)
			{
				delete k;
				return STATUS_NOT_SUPPORTED;
			}
			memcpy(k->p.data(), pbInput, k->p.size());
			memcpy(k->s.data(), pbInput + k->p.size(), k->s.size());
			*phKey = k;
			return STATUS_SUCCESS;
		}
		return STATUS_NOT_SUPPORTED;
	};

	m.GenerateKeyPair = [](_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_    BCRYPT_KEY_HANDLE* phKey,
		_In_     ULONG dwLength,
		_In_     ULONG dwFlags
		)
	{
		BOP* k = (BOP*)hAlgorithm;
		if (dynamic_cast<DIL2*>(k))
		{
			auto k = new DIL(2);
			uint8_t seed[32] = {};
			uint8_t pubkey[dilithium2::PubKeyLen];
			uint8_t seckey[dilithium2::SecKeyLen];
			prng::prng_t prng;
			prng.read(seed, sizeof(seed));
			dilithium2::keygen(seed, pubkey, seckey);
			k->p.resize(sizeof(pubkey));
			memcpy(k->p.data(), pubkey, k->p.size());
			k->s.resize(sizeof(seckey));
			memcpy(k->s.data(), seckey, k->s.size());

			*phKey = k;
			return STATUS_SUCCESS;
		}
		if (dynamic_cast<DIL3*>(k))
		{
			auto k = new DIL(3);
			uint8_t seed[32] = {};
			uint8_t pubkey[dilithium3::PubKeyLen];
			uint8_t seckey[dilithium3::SecKeyLen];
			prng::prng_t prng;
			prng.read(seed, sizeof(seed));
			dilithium3::keygen(seed, pubkey, seckey);
			k->p.resize(sizeof(pubkey));
			memcpy(k->p.data(), pubkey, k->p.size());
			k->s.resize(sizeof(seckey));
			memcpy(k->s.data(), seckey, k->s.size());

			*phKey = k;
			return STATUS_SUCCESS;
		}
		if (dynamic_cast<DIL5*>(k))
		{
			auto k = new DIL(5);
			uint8_t seed[32] = {};
			uint8_t pubkey[dilithium5::PubKeyLen];
			uint8_t seckey[dilithium5::SecKeyLen];
			prng::prng_t prng;
			prng.read(seed, sizeof(seed));
			dilithium5::keygen(seed, pubkey, seckey);
			k->p.resize(sizeof(pubkey));
			memcpy(k->p.data(), pubkey, k->p.size());
			k->s.resize(sizeof(seckey));
			memcpy(k->s.data(), seckey, k->s.size());

			*phKey = k;
			return STATUS_SUCCESS;
		}
		return STATUS_NOT_SUPPORTED;
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
		PKA* a = (PKA*)hKey;
		if (auto k = dynamic_cast<DIL*>(a))
		{
			uint8_t msg[32];
			prng::prng_t prng;
			prng.read(msg, sizeof(msg));

			size_t sigs = 0;
			if (k->t == 2)
				sigs = dilithium2::SigLen;
			if (k->t == 3)
				sigs = dilithium3::SigLen;
			if (k->t == 5)
				sigs = dilithium5::SigLen;
			*pcbResult = (DWORD)sigs;
			if (!pbOutput || !cbOutput)
				return STATUS_SUCCESS;
			if (cbOutput != sigs)
				return STATUS_NOT_SUPPORTED;

			if (k->t == 2)
				dilithium2::sign<false>(k->s.data(), (uint8_t*)pbInput, (DWORD)cbInput, pbOutput, nullptr);
			if (k->t == 3)
				dilithium3::sign<false>(k->s.data(), (uint8_t*)pbInput, (DWORD)cbInput, pbOutput, nullptr);
			if (k->t == 5)
				dilithium5::sign<false>(k->s.data(), (uint8_t*)pbInput, (DWORD)cbInput, pbOutput, nullptr);
			return STATUS_SUCCESS;
		}
		return STATUS_NOT_SUPPORTED;

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
		PKA* a = (PKA*)hKey;
		if (auto k = dynamic_cast<DIL*>(a))
		{
			bool z = 0;
			if (k->t == 2)
				z = dilithium2::verify(k->p.data(), pbHash, cbHash, pbSignature);
			if (k->t == 3)
				z = dilithium3::verify(k->p.data(), pbHash, cbHash, pbSignature);
			if (k->t == 5)
				z = dilithium5::verify(k->p.data(), pbHash, cbHash, pbSignature);

			if (z)
				return STATUS_SUCCESS;
			return STATUS_INVALID_SIGNATURE;
		}
		return STATUS_NOT_SUPPORTED;

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
		PKA* a = (PKA*)hKey;
		if (auto k = dynamic_cast<DIL*>(a))
		{
			auto needs = k->p.size() + k->s.size();
			*pcbResult = (ULONG)needs;
			if (!pbOutput || !cbOutput)
				return STATUS_SUCCESS;
			if (cbOutput < needs)
				return STATUS_NOT_SUPPORTED;
			memcpy(pbOutput, k->p.data(), k->p.size());
			memcpy(pbOutput + k->p.size(), k->s.data(), k->s.size());
			return ERROR_SUCCESS;
		}
		
		return STATUS_NOT_SUPPORTED;
	};
	m.DestroyKey = [](_Inout_  BCRYPT_KEY_HANDLE hKey
		)
	{
		if (!hKey)
			return (NTSTATUS)-1;
		PKA* ctx = (PKA*)hKey;
		delete ctx;
		return (NTSTATUS)STATUS_SUCCESS;
	};




	m.Version = BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE_VERSION_1;
	return ERROR_SUCCESS;
}

