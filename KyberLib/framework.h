#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#pragma warning(disable:4005)
#include <windows.h>
#undef min
#undef max
#include <ncrypt.h>
#include <array>
#include <bcrypt_provider.h>
#include <ncrypt_provider.h>
#include <vector>
#include <map>
#include <memory>
#include <ntstatus.h>
#include "..\\common.h"


