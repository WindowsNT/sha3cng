# cngsha3

An implementation of SHA-3 (using librhash https://github.com/rhash/RHash/tree/master/librhash) into CNG (Cryptography New Generation) API so all Windows apps can use SHA-3.
Visual Studio 2022 Solution included.

# Algorithms
Supports SHA-224, SHA-256, SHA-384 and SHA-512

# Defines
The names are:

* #define SHA3_224_ALGORITHM  L"SHA3-224"
* #define SHA3_256_ALGORITHM  L"SHA3-256"
* #define SHA3_384_ALGORITHM  L"SHA3-384"
* #define SHA3_512_ALGORITHM  L"SHA3-512"
* const wchar_t* ProviderB = L"Michael Chourdakis CNG SHA-3 Implementation";

# Instructions
* Install the Cryptographic Provider SDK (https://www.microsoft.com/en-us/download/details.aspx?id=30688)
* In both dll and test project properties, set the C++ include path to the above CNG SDK (mine is set at c:\Windows Kits\10\Cryptographic Provider Development Kit\include)
* Build the project
* The output dll.dll can be registered with regsvr32 (run as admin). You are ready to use the above names in CNG.
* Alternatively, run test as admin, it demonstrates a simple usage.


