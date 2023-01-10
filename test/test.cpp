// test.cpp : Defines the entry point for the application.
//
#include <windows.h>


int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	auto h = LoadLibrary(L"dll.dll");
	if (!h)
		return 0;
	typedef HRESULT(__stdcall* r4)();

	r4 R = (r4)GetProcAddress(h, "DllUnregisterServer");
	if (R)
		R();
	R = (r4)GetProcAddress(h, "DllRegisterServer");
	if (R)
		R();

	R = (r4)GetProcAddress(h, "DllUnregisterServer");
	if (R)
		R();
	if (R)
		R();
}