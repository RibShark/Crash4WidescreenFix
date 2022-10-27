#include "stdafx.h"

#define HOOKED_FUNCTION GetCommandLineW
#define HOOKED_LIBRARY "KERNEL32.DLL"

#include "HookInit.hpp"