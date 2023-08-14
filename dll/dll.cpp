#pragma warning(disable:4005)
#include <windows.h>
#undef min
#include <ncrypt.h>
#include <array>
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

namespace SHA3
{
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

	class BOP224 : public BOP
	{
	public:

		virtual bool un() { return 1; }

	};
	class BOP256 : public BOP
	{
	public:

		virtual bool un() { return 1; }

	};
	class BOP384 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};
	class BOP512 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};
	class HASH224 : public HASH
	{
	public:

		virtual void init()
		{
			rhash_sha3_224_init(&ctx);
			rr.resize(28);
		}
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

	class HASH384 : public HASH
	{
	public:

		virtual void init()
		{
			rhash_sha3_384_init(&ctx);
			rr.resize(48);
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
		if (wcsicmp(pszAlgId, SHA3_224_ALGORITHM) != 0 && wcsicmp(pszAlgId, SHA3_256_ALGORITHM) != 0 && wcsicmp(pszAlgId, SHA3_512_ALGORITHM) != 0 && wcsicmp(pszAlgId, SHA3_384_ALGORITHM) != 0)
			return -1;
		BCRYPT_HASH_FUNCTION_TABLE m;
		*ppFunctionTable = &m;


		m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
			_In_   LPCWSTR pszAlgId,
			_In_   ULONG dwFlags
			) -> NTSTATUS
		{
			BOP* b = 0;
			if (wcsicmp(pszAlgId, SHA3_224_ALGORITHM) == 0)
				b = new BOP224;
			if (wcsicmp(pszAlgId, SHA3_256_ALGORITHM) == 0)
				b = new BOP256;
			if (wcsicmp(pszAlgId, SHA3_384_ALGORITHM) == 0)
				b = new BOP384;
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
					if (dynamic_cast<BOP224*>((BOP*)hObject))
						r = sizeof(BOP224);
					if (dynamic_cast<BOP256*>((BOP*)hObject))
						r = sizeof(BOP256);
					if (dynamic_cast<BOP384*>((BOP*)hObject))
						r = sizeof(BOP384);
					if (dynamic_cast<BOP512*>((BOP*)hObject))
						r = sizeof(BOP512);
					if (dynamic_cast<HASH224*>((HASH*)hObject))
						r = sizeof(HASH224);
					if (dynamic_cast<HASH256*>((HASH*)hObject))
						r = sizeof(HASH256);
					if (dynamic_cast<HASH384*>((HASH*)hObject))
						r = sizeof(HASH384);
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
					if (dynamic_cast<HASH224*>((HASH*)hObject))
						r = 28;
					if (dynamic_cast<HASH384*>((HASH*)hObject))
						r = 48;
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
				return (NTSTATUS)-1;
			if (pbSecret)
				return (NTSTATUS)-1;
			BOP* b = (BOP*)hAlgorithm;
			HASH* ctx = 0;
			if (dynamic_cast<BOP224*>(b))
				ctx = new HASH224;
			if (dynamic_cast<BOP256*>(b))
				ctx = new HASH256;
			if (dynamic_cast<BOP384*>(b))
				ctx = new HASH384;
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
			if (dynamic_cast<HASH224*>(ctx))
				a1 = new HASH224;
			if (dynamic_cast<HASH256*>(ctx))
				a1 = new HASH256;
			if (dynamic_cast<HASH384*>(ctx))
				a1 = new HASH384;
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

}

#include "..\\kyber\\include\\kyber512_kem.hpp"
#include "..\\kyber\\include\\kyber768_kem.hpp"
#include "..\\kyber\\include\\kyber1024_kem.hpp"
#include "..\\kyber\\include\\pke.hpp"

//#include "..\\dilithium\\include\\dilithium5.hpp"
//#include "..\\dilithium\\include\\dilithium3.hpp"
//#include "..\\dilithium\\include\\dilithium2.hpp"
//#include "..\\dilithium\\include\\dilithium.hpp"


namespace PK_ALGORITHMS
{

	class PKA
	{
	public:
		virtual void nu() {}
		virtual ~PKA()
		{

		}
	};

	class KYBER : public PKA
	{
	public:
		int b = 0;
		std::vector<uint8_t> d, z, p, s;

		KYBER(int bits = 512)
		{
			b = bits;
		}

		virtual ~KYBER()
		{

		}
	};

	class BOP
	{
	public:

		virtual bool un() = 0;

	};

	class KYBER512 : public BOP
	{
	public:
			virtual bool un() { return 1; }
	};
	class KYBER768 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};
	class KYBER1024 : public BOP
	{
	public:
		virtual bool un() { return 1; }
	};



	NTSTATUS WINAPI GetAsymmetricEncryptionInterface(
		_In_   LPCWSTR pszProviderName,
		_In_   LPCWSTR pszAlgId,
		_Out_  BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE** ppFunctionTable,
		_In_   ULONG dwFlags
	)
	{
		if (!ppFunctionTable)
			return -1;
		if (wcsicmp(pszAlgId,KYBER_512_ALGORITHM) != 0 && wcsicmp(pszAlgId, KYBER_768_ALGORITHM) != 0 && wcsicmp(pszAlgId, KYBER_1024_ALGORITHM) != 0)
			return -1;

		BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE m = {};
		*ppFunctionTable = &m;

		m.OpenAlgorithmProvider = [](_Out_  BCRYPT_ALG_HANDLE* phAlgorithm,
			_In_   LPCWSTR pszAlgId,
			_In_   ULONG dwFlags
			) -> NTSTATUS
		{
			BOP* b = 0;
			if (wcsicmp(pszAlgId, KYBER_512_ALGORITHM) == 0)
				b = new KYBER512;
			if (wcsicmp(pszAlgId, KYBER_768_ALGORITHM) == 0)
				b = new KYBER768;
			if (wcsicmp(pszAlgId, KYBER_1024_ALGORITHM) == 0)
				b = new KYBER1024;
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
			
			if (wcsicmp(pszProperty, BCRYPT_PADDING_SCHEMES) == 0)
			{
				if (!pcbResult)
					return (NTSTATUS)-1;
				if (pbOutput == 0)
					*pcbResult = 4;
				else
				{
					DWORD r = 0; // BCRYPT_SUPPORTED_PAD_ROUTER ? 
					memcpy(pbOutput, &r, 4);
					*pcbResult = 4;
				}
				return ERROR_SUCCESS;

			}
			if (wcsicmp(pszProperty, BCRYPT_OBJECT_LENGTH) == 0)
			{
				if (!pcbResult)
					return (NTSTATUS)-1;
				if (pbOutput == 0)
					*pcbResult = 4;
				else
				{
					DWORD r = sizeof(BOP);
					if (dynamic_cast<KYBER512*>((BOP*)hObject))
						r = sizeof(KYBER512);
					if (dynamic_cast<KYBER768*>((BOP*)hObject))
						r = sizeof(KYBER768);
					if (dynamic_cast<KYBER1024*>((BOP*)hObject))
						r = sizeof(KYBER1024);

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


/*		m.GenerateKey = [](_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
			_Out_    BCRYPT_KEY_HANDLE* phKey,
			_Out_    PUCHAR pbKeyObject,
			_In_     ULONG cbKeyObject,
			_In_     PUCHAR pbSecret,
			_In_     ULONG cbSecret,
			_In_     ULONG dwFlags
			)
		{
			if (!hAlgorithm)
				return (NTSTATUS)-1;
			if (pbSecret)
				return (NTSTATUS)-1;
			BOP* b = (BOP*)hAlgorithm;
			KYBER* ctx = 0;
			if (dynamic_cast<KYBER512*>(b))
				ctx = new KYBER(512);
			if (dynamic_cast<KYBER768*>(b))
				ctx = new KYBER(768);
			if (dynamic_cast<KYBER1024*>(b))
				ctx = new KYBER(1024);
			if (!ctx)
				return (NTSTATUS)-1;

			return STATUS_NOT_SUPPORTED;
		};
*/
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
			PKA* a = (PKA*)hKey;
			if (auto k = dynamic_cast<KYBER*>(a))
			{
				if (cbInput != 32)
					return STATUS_NOT_SUPPORTED;

				if (k->b == 512)
				{
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = kyber512_kem::CIPHER_LEN;
						return STATUS_SUCCESS;
					}
					if (cbOutput < kyber512_kem::CIPHER_LEN)
						return STATUS_INVALID_PARAMETER;

					prng::prng_t prng;
					uint8_t coin[32] = {};
					prng.read(coin, 32);

					pke::encrypt<2, 3, 2, 10, 4>((const uint8_t* const __restrict)k->p.data(), (const uint8_t* const __restrict)pbInput, (const uint8_t* const __restrict)coin, (uint8_t* const __restrict)pbOutput);
					*pcbResult = kyber512_kem::CIPHER_LEN;
					return STATUS_SUCCESS;
				}

				if (k->b == 768)
				{
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = kyber768_kem::CIPHER_LEN;
						return STATUS_SUCCESS;
					}
					if (cbOutput < kyber768_kem::CIPHER_LEN)
						return STATUS_INVALID_PARAMETER;

					prng::prng_t prng;
					uint8_t coin[32] = {};
					prng.read(coin, 32);

					pke::encrypt<3, 2, 2, 10, 4>((const uint8_t* const __restrict)k->p.data(), (const uint8_t* const __restrict)pbInput, (const uint8_t* const __restrict)coin, (uint8_t* const __restrict)pbOutput);
					*pcbResult = kyber768_kem::CIPHER_LEN;
					return STATUS_SUCCESS;
				}

				if (k->b == 1024)
				{
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = kyber1024_kem::CIPHER_LEN;
						return STATUS_SUCCESS;
					}
					if (cbOutput < kyber1024_kem::CIPHER_LEN)
						return STATUS_INVALID_PARAMETER;

					prng::prng_t prng;
					uint8_t coin[32] = {};
					prng.read(coin, 32);

					pke::encrypt<4, 2, 2, 11, 5>((const uint8_t* const __restrict)k->p.data(), (const uint8_t* const __restrict)pbInput, (const uint8_t* const __restrict)coin, (uint8_t* const __restrict)pbOutput);
					*pcbResult = kyber1024_kem::CIPHER_LEN;
					return STATUS_SUCCESS;
				}
			}
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

			PKA* a = (PKA*)hKey;
			if (auto k = dynamic_cast<KYBER*>(a))
			{
				if (k->b == 512)
				{
					if (cbInput != kyber512_kem::CIPHER_LEN)
						return STATUS_NOT_SUPPORTED;
					std::vector<uint8_t> cipher(32);
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = 32;
						return STATUS_SUCCESS;
					}
					if (cbOutput < 32)
						return STATUS_INVALID_PARAMETER;
					pke::decrypt<2, 10, 4>(k->s.data(), pbInput, pbOutput);
					*pcbResult = 32;
					return STATUS_SUCCESS;
				}
				if (k->b == 768)
				{
					if (cbInput != kyber768_kem::CIPHER_LEN)
						return STATUS_NOT_SUPPORTED;
					std::vector<uint8_t> cipher(32);
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = 32;
						return STATUS_SUCCESS;
					}
					if (cbOutput < 32)
						return STATUS_INVALID_PARAMETER;
					pke::decrypt<3, 10, 4>(k->s.data(), pbInput, pbOutput);
					*pcbResult = 32;
					return STATUS_SUCCESS;
				}
				if (k->b == 1024)
				{
					if (cbInput != kyber1024_kem::CIPHER_LEN)
						return STATUS_NOT_SUPPORTED;
					std::vector<uint8_t> cipher(32);
					if (!pbOutput || !cbOutput)
					{
						*pcbResult = 32;
						return STATUS_SUCCESS;
					}
					if (cbOutput < 32)
						return STATUS_INVALID_PARAMETER;
					pke::decrypt<4, 11, 5>(k->s.data(), pbInput, pbOutput);
					*pcbResult = 32;
					return STATUS_SUCCESS;
				}
			}
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
			if (dynamic_cast<KYBER512*>(k))
			{
				auto k = new KYBER(512);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber512_kem::PKEY_LEN);
				k->s.resize(kyber512_kem::SKEY_LEN);
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
			if (dynamic_cast<KYBER768*>(k))
			{
				auto k = new KYBER(768);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber768_kem::PKEY_LEN);
				k->s.resize(kyber768_kem::SKEY_LEN);
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
			if (dynamic_cast<KYBER1024*>(k))
			{
				auto k = new KYBER(1024);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber1024_kem::PKEY_LEN);
				k->s.resize(kyber1024_kem::SKEY_LEN);
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
			if (dynamic_cast<KYBER512*>(k))
			{
				auto k = new KYBER(512);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber512_kem::PKEY_LEN);
				k->s.resize(kyber512_kem::SKEY_LEN);
				kyber512_kem::keygen(k->d.data(), k->z.data(), k->p.data(), k->s.data());
				*phKey = k;
				return STATUS_SUCCESS;
			}
			if (dynamic_cast<KYBER768*>(k))
			{
				auto k = new KYBER(768);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber768_kem::PKEY_LEN);
				k->s.resize(kyber768_kem::SKEY_LEN);
				kyber768_kem::keygen(k->d.data(), k->z.data(), k->p.data(), k->s.data());
				*phKey = k;
				return STATUS_SUCCESS;
			}
			if (dynamic_cast<KYBER1024*>(k))
			{
				auto k = new KYBER(1024);
				k->d.resize(32);
				k->z.resize(32);
				prng::prng_t prng;
				prng.read(k->d.data(), k->d.size());
				prng.read(k->z.data(), k->z.size());
				k->p.resize(kyber1024_kem::PKEY_LEN);
				k->s.resize(kyber1024_kem::SKEY_LEN);
				kyber1024_kem::keygen(k->d.data(), k->z.data(), k->p.data(), k->s.data());
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
			return STATUS_NOT_SUPPORTED;

		};

		

		/*
		m.DuplicateKey = [](_In_   BCRYPT_KEY_HANDLE hKey,
			_Out_  BCRYPT_KEY_HANDLE* phNewKey,
			_Out_  PUCHAR pbKeyObject,
			_In_   ULONG cbKeyObject,
			_In_   ULONG dwFlags)
		{
			return STATUS_NOT_SUPPORTED;
		};


		m.ImportKey = [](_In_     BCRYPT_ALG_HANDLE hAlgorithm,
			_Inout_  BCRYPT_KEY_HANDLE hImportKey,
			_In_     LPCWSTR pszBlobType,
			_Out_    BCRYPT_KEY_HANDLE* phKey,
			_Out_    PUCHAR pbKeyObject,
			_In_     ULONG cbKeyObject,
			_In_     PUCHAR pbInput,
			_In_     ULONG cbInput,
			_In_     ULONG dwFlags
			)
		{
			return STATUS_NOT_SUPPORTED;
		};
		*/
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
			if (auto k = dynamic_cast<KYBER*>(a))
			{
				std::vector<uint8_t> m(32);
				std::vector<uint8_t> cipher;
				std::vector<uint8_t> shrd_key0(32);
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
}

NTSTATUS WINAPI GetAsymmetricEncryptionInterface(
	_In_   LPCWSTR pszProviderName,
	_In_   LPCWSTR pszAlgId,
	_Out_  BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE** ppFunctionTable,
	_In_   ULONG dwFlags
)
{
	return PK_ALGORITHMS::GetAsymmetricEncryptionInterface(pszProviderName, pszAlgId, ppFunctionTable, dwFlags);
}

NTSTATUS WINAPI GetHashInterface(
	_In_   LPCWSTR pszProviderName,
	_In_   LPCWSTR pszAlgId,
	_Out_  BCRYPT_HASH_FUNCTION_TABLE** ppFunctionTable,
	_In_   ULONG dwFlags
)
{
	return SHA3::GetHashInterface(pszProviderName, pszAlgId, ppFunctionTable, dwFlags);
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
	CRYPT_INTERFACE_REG* rif[2] = {};
	CRYPT_INTERFACE_REG r1 = {};
	CRYPT_INTERFACE_REG r2 = {};
	reg.pUM->rgpInterfaces = rif;
	rif[0] = &r1;
	rif[1] = &r2;
	r1.dwInterface = BCRYPT_HASH_INTERFACE;
	r2.dwInterface = BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
	PWSTR u[] = { (PWSTR)SHA3_224_ALGORITHM,(PWSTR)SHA3_256_ALGORITHM,(PWSTR)SHA3_384_ALGORITHM,(PWSTR)SHA3_512_ALGORITHM };
	r1.rgpszFunctions = u;
	r1.cFunctions = 4;
	PWSTR u2[] = { (PWSTR)KYBER_512_ALGORITHM,(PWSTR)KYBER_768_ALGORITHM,(PWSTR)KYBER_1024_ALGORITHM };
	r2.rgpszFunctions = u2;
	r2.cFunctions = 3;

	reg.pUM->cInterfaces = 2;

	auto st = BCryptRegisterProvider(ProviderB, CRYPT_OVERWRITE, &reg);
	if (st == STATUS_OBJECT_NAME_COLLISION)
		MessageBeep(0);
	if (st != 0)
		return E_FAIL;
	
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_224_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_256_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_384_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	BCryptAddContextFunctionProvider(CRYPT_LOCAL, 0, BCRYPT_HASH_INTERFACE, SHA3_512_ALGORITHM, ProviderB, CRYPT_PRIORITY_TOP);
	return S_OK;
}

HRESULT __stdcall DllUnregisterServer()
{
	std::vector<wchar_t> y(1000);
	GetSystemDirectory(y.data(), 1000);
	wcscat_s(y.data(), 1000, L"\\cngsha3.dll");

	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_224_ALGORITHM, ProviderB);
	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_256_ALGORITHM, ProviderB);
	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_384_ALGORITHM, ProviderB);
	BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, ProviderB, BCRYPT_HASH_INTERFACE, SHA3_512_ALGORITHM, ProviderB);

	BCryptUnregisterProvider(ProviderB);
	DeleteFile(y.data());
	return S_OK;
}
