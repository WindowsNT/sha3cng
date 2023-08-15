# cngsha3

An implementation of New algorhtms into CNG (Cryptography New Generation) API so all Windows apps can use them.
Visual Studio 2022 Solution included.

CodeProject Article: https://www.codeproject.com/Articles/5351727/cngsha3-A-Cryptography-Next-Generation-Implementat

# Algorithms
SHA-3 (using librhash https://github.com/rhash/RHash/tree/master/librhash)
Supports SHA-224, SHA-256, SHA-384 and SHA-512

CRYSTALS-Kyber: https://github.com/itzmeanjan/kyber
Supports 512,768,1024 bits

CRYSTALS-Dilithium: https://github.com/itzmeanjan/dilithium
Supports 2,3,5

CRYSTALS-Sphincs: https://github.com/itzmeanjan/sphincs

# Defines
The names are:

```
const wchar_t* ProviderB = L"Michael Chourdakis CNG Implementations";
#define SHA3_224_ALGORITHM  L"SHA3-224"
#define SHA3_256_ALGORITHM  L"SHA3-256"
#define SHA3_384_ALGORITHM  L"SHA3-384"
#define SHA3_512_ALGORITHM  L"SHA3-512"
#define KYBER_512_ALGORITHM  L"KYBER-512"
#define KYBER_768_ALGORITHM  L"KYBER-768"
#define KYBER_1024_ALGORITHM  L"KYBER-1024"
#define DILITHIUM_2_ALGORITHM  L"DILITHIUM-2"
#define DILITHIUM_3_ALGORITHM  L"DILITHIUM-3"
#define DILITHIUM_5_ALGORITHM  L"DILITHIUM-5"
#define SPHINCS_ALGORITHM  L"SPHINCS"

```

# Instructions
* Install the Cryptographic Provider SDK (https://www.microsoft.com/en-us/download/details.aspx?id=30688)
* In both dll and test project properties, set the C++ include path to the above CNG SDK (mine is set at c:\Windows Kits\10\Cryptographic Provider Development Kit\include)
* Build the project
* The output dll.dll can be registered with regsvr32 (run as admin). You are ready to use the above names in CNG.
* Alternatively, run test as admin, it demonstrates a simple usage.


