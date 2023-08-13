// test.cpp : Defines the entry point for the application.
//
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include "..\\common.h"

#pragma comment(lib,"bcrypt.lib")

#include "..\\dll\\sha3.hpp"
class HASH
{
	BCRYPT_ALG_HANDLE h;
	BCRYPT_HASH_HANDLE ha;
public:

	HASH(LPCWSTR alg = SHA3_256_ALGORITHM)
	{
		BCryptOpenAlgorithmProvider(&h, alg, 0, 0);
		if (h)
			BCryptCreateHash(h, &ha, 0, 0, 0, 0, 0);
	}

	bool hash(const BYTE* d, DWORD sz)
	{
		if (!ha)
			return false;
		auto nt = BCryptHashData(ha, (UCHAR*)d, sz, 0);
		return (nt == 0) ? true : false;
	}

	bool get(std::vector<BYTE>& b)
	{
		DWORD hl;
		ULONG rs;
		if (!ha)
			return false;
		auto nt = BCryptGetProperty(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&hl, sizeof(DWORD), &rs, 0);
		if (nt != 0)
			return false;
		b.resize(hl);
		nt = BCryptFinishHash(ha, b.data(), hl, 0);
		if (nt != 0)
			return false;
		return true;
	}

	~HASH()
	{
		if (ha)
			BCryptDestroyHash(ha);
		ha = 0;
		if (h)
			BCryptCloseAlgorithmProvider(h, 0);
		h = 0;
	}
};


/*
class ED
{
	BCRYPT_ALG_HANDLE h;
	BCRYPT_HASH_HANDLE ha;
public:

	ED(LPCWSTR alg = KYBER_512_ALGORITHM,const char* pwd = 0,size_t pwdlen = 0)
	{
		BCryptOpenAlgorithmProvider(&h, alg, 0, 0);
		if (h)
		{
//			HASH h2(BCRYPT_SHA256_ALGORITHM);
			HASH h2(SHA3_256_ALGORITHM);
			h2.hash((BYTE*)pwd, (DWORD)pwdlen);
			std::vector<unsigned char> rx;
			h2.get(rx);
			BCryptGenerateSymmetricKey(h, &ha, 0, 0, (PUCHAR)rx.data(), (ULONG)rx.size(), 0);
		}
	}

	bool e(const BYTE* d, DWORD sz,std::vector<unsigned char>& out)
	{
		if (!ha)
			return false;
		ULONG u = 0;
		auto nt = BCryptEncrypt(ha, (UCHAR*)d, sz, 0,0,0,0,0,&u, BCRYPT_BLOCK_PADDING);
		if (nt == 0)
		{
			out.resize(u);
			nt = BCryptEncrypt(ha, (UCHAR*)d,(ULONG) sz, 0, 0, 0, (PUCHAR)out.data(), (ULONG)out.size(), &u, BCRYPT_BLOCK_PADDING);
			out.resize(u);
		}
		return (nt == 0) ? true : false;
	}

	bool d(const BYTE* d, DWORD sz, std::vector<unsigned char>& out)
	{
		if (!ha)
			return false;
		ULONG u = 0;
		auto nt = BCryptDecrypt(ha, (UCHAR*)d, sz, 0, 0, 0, 0, 0, &u, BCRYPT_BLOCK_PADDING);
		if (nt == 0)
		{
			out.resize(u);
			nt = BCryptDecrypt(ha, (UCHAR*)d, (ULONG)sz, 0, 0, 0, (PUCHAR)out.data(), (ULONG)out.size(), &u, BCRYPT_BLOCK_PADDING);
			out.resize(u);
		}
		return (nt == 0) ? true : false;
	}

	~ED()
	{
		if (ha)
			BCryptDestroyKey(ha);
		ha = 0;
		if (h)
			BCryptCloseAlgorithmProvider(h, 0);
		h = 0;
	}
};

*/

class PK
{
	BCRYPT_ALG_HANDLE h;
	BCRYPT_HASH_HANDLE ha;
public:

	PK(LPCWSTR alg = KYBER_512_ALGORITHM,int bits = 1024)
	{
		BCryptOpenAlgorithmProvider(&h, alg, 0, 0);
		if (h)
		{
			auto st = BCryptGenerateKeyPair(h, &ha, bits, 0);
			st = BCryptFinalizeKeyPair(ha, 0);
/*			//			HASH h2(BCRYPT_SHA256_ALGORITHM);
			HASH h2(SHA3_256_ALGORITHM);
			h2.hash((BYTE*)pwd, (DWORD)pwdlen);
			std::vector<unsigned char> rx;
			h2.get(rx);
			BCryptGenerateSymmetricKey(h, &ha, 0, 0, (PUCHAR)rx.data(), (ULONG)rx.size(), 0);
			*/
		}
	}

	bool e(const BYTE* d, DWORD sz, std::vector<unsigned char>& out,HASH* h = 0)
	{
		if (!ha)
			return false;
		ULONG u = 0;

		std::vector<unsigned char> HashInstead;
		auto nt = BCryptEncrypt(ha, (UCHAR*)d, sz, 0, 0, 0, 0, 0, &u, BCRYPT_PAD_PKCS1);
		if (nt == 0)
		{
			out.resize(u);
			nt = BCryptEncrypt(ha, (UCHAR*)d, (ULONG)sz, 0, 0, 0, (PUCHAR)out.data(), (ULONG)out.size(), &u, BCRYPT_PAD_PKCS1);
			out.resize(u);
		}
		return (nt == 0) ? true : false;
	}

	bool d(const BYTE* d, DWORD sz, std::vector<unsigned char>& out)
	{
		if (!ha)
			return false;
		ULONG u = 0;
		auto nt = BCryptDecrypt(ha, (UCHAR*)d, sz, 0, 0, 0, 0, 0, &u, BCRYPT_PAD_PKCS1);
		if (nt == 0)
		{
			out.resize(u);
			nt = BCryptDecrypt(ha, (UCHAR*)d, (ULONG)sz, 0, 0, 0, (PUCHAR)out.data(), (ULONG)out.size(), &u, BCRYPT_PAD_PKCS1);
			out.resize(u);
		}
		return (nt == 0) ? true : false;
	}

	~PK()
	{
		if (ha)
			BCryptDestroyKey(ha);
		ha = 0;
		if (h)
			BCryptCloseAlgorithmProvider(h, 0);
		h = 0;
	}
};




int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	auto h = LoadLibrary(L"dll.dll");
	if (!h)
		return 0;
	typedef HRESULT(__stdcall* r4)();

	auto R = (r4)GetProcAddress(h, "DllRegisterServer");
	if (R)
		R();

	if (1)
	{
		// With existing algoriths
		// HASH hash(BCRYPT_SHA256_ALGORITHM);

		// New ones
		//	HASH hash(SHA3_224_ALGORITHM);
		HASH hash(SHA3_256_ALGORITHM);
		//	HASH hash(SHA3_384_ALGORITHM);
		//	HASH hash(SHA3_512_ALGORITHM);
		hash.hash((BYTE*)"Hello", 5);
		std::vector<BYTE> v;
		hash.get(v);
	}

	if (1)
	{
		// Can be used with existing algorithms
//		PK e(BCRYPT_RSA_ALGORITHM);

		// New algorithms
//		PK e(KYBER_512_ALGORITHM);
//		PK e(KYBER_768_ALGORITHM);
		PK e(KYBER_1024_ALGORITHM);
		std::vector<unsigned char> out1;
		std::vector<unsigned char> out2;

		// 32 bytes for KYBER PKI input so let's hash our data with SHA-3 256
		HASH hash(SHA3_256_ALGORITHM);
		std::vector<unsigned char> outx(32);
		hash.hash((BYTE*)"Hello", 5);
		hash.get(outx);
		e.e((const BYTE*)outx.data(), (DWORD)outx.size(), out1);
		e.d(out1.data(), (ULONG)out1.size(), out2);
		assert(memcmp(outx.data(), out2.data(), out2.size()) == 0);
	}


	R = (r4)GetProcAddress(h, "DllUnregisterServer");
	if (R)
		R();
	return 0;
}