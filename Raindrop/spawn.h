#ifndef _SPAWN_H_
#define _SPAWN_H_

#include "stdafx.h"

#define BUFFER_SIZE_PIPE 1048576

DWORD  GetParentProcess();

bool CreatePipes(HANDLE& hInputPipeRead, HANDLE& hInputPipeWrite, HANDLE& hOutputPipeRead, HANDLE& hOutputPipeWrite);

void InitConsole(HANDLE& hOldStdIn, HANDLE& hOldStdOut, HANDLE& hOldStdErr);

void RestoreStdHandles(HANDLE hOldStdIn, HANDLE hOldStdOut, HANDLE hOldStdErr);

bool EnableVirtualTerminalSequenceProcessing();

HRESULT CreatePseudoConsoleWithPipes(HPCON* phPseudoConsole, HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols);

#endif
