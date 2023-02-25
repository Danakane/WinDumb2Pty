#ifndef GLOBALS_H
#define GLOBALS_H

#include "stdafx.h"

extern HANDLE g_hStdIn;
extern HANDLE g_hStdOut;
extern HANDLE g_hStdErr;
extern DWORD g_dwNbBytes;

#define WriteStdIn(x) WriteFile(g_hStdIn, x, (DWORD)strlen(x), &g_dwNbBytes, NULL)
#define WriteStdOut(x) WriteFile(g_hStdOut, x, (DWORD)strlen(x), &g_dwNbBytes, NULL)
#define WriteStdErr(x) WriteFile(g_hStdErr, x, (DWORD)strlen(x), &g_dwNbBytes, NULL)

#endif // GLOBALS_H
