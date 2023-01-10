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




int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	auto h = LoadLibrary(L"dll.dll");
	if (!h)
		return 0;
	typedef HRESULT(__stdcall* r4)();

	auto R = (r4)GetProcAddress(h, "DllRegisterServer");
	if (R)
		R();

	//	HASH hash(SHA3_224_ALGORITHM);
		HASH hash(SHA3_256_ALGORITHM);
	//	HASH hash(SHA3_384_ALGORITHM);
	//	HASH hash(SHA3_512_ALGORITHM);
	hash.hash((BYTE*)"Hello", 5);
	std::vector<BYTE> v;
	hash.get(v);

	R = (r4)GetProcAddress(h, "DllUnregisterServer");
	if (R)
		R();
	return 0;
}