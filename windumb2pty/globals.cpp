#include "globals.h"

HANDLE g_hStdIn = GetStdHandle(STD_INPUT_HANDLE);
HANDLE g_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
HANDLE g_hStdErr = GetStdHandle(STD_ERROR_HANDLE);
DWORD g_dwNbBytes = 0;