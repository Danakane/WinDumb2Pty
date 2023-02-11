#ifndef _SPAWN_H_
#define _SPAWN_H_

#include "stdafx.h"

#define BUFFER_SIZE_PIPE 1048576

#define BUFFER_SIZE_SOCKET 8192

DWORD  GetParentProcess();

bool CreatePipes(HANDLE& hInputPipeRead, HANDLE& hInputPipeWrite, HANDLE& hOutputPipeRead, HANDLE& hOutputPipeWrite);

void InitConsole(HANDLE& hOldStdIn, HANDLE& hOldStdOut, HANDLE& hOldStdErr);

void RestoreStdHandles(HANDLE hOldStdIn, HANDLE hOldStdOut, HANDLE hOldStdErr);

bool EnableVirtualTerminalSequenceProcessing();

HRESULT CreatePseudoConsoleWithPipes(HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols, OUT HPCON* phPseudoConsole);

HRESULT ConfigureProcessThread(HPCON* phPseudoConsole, DWORD_PTR pAttributes, OUT STARTUPINFOEX* pStartupInfo);

HRESULT RunProcess(STARTUPINFOEX& startupInfo, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo);

typedef struct _ReadPipeWriteSocketThreadParams 
{
	HANDLE hPipe;
	SOCKET hSock;
	bool bOverlapped;
} ReadPipeWriteSocketThreadParams;

DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams);

HANDLE StartThreadReadPipeWriteSocket(HANDLE hPipe, SOCKET hSock, bool overlappedSocket);

typedef struct _ReadSocketWritePipeThreadParams
{
	HANDLE hPipe;
	SOCKET hSock;
	HANDLE hChildProcess;
	bool bOverlapped;
} ReadSocketWritePipeThreadParams;

DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams);

HANDLE StartThreadReadSocketWritePipe(HANDLE hPipe, SOCKET hSock, HANDLE hChildProcess, bool bOverlappedSocket);

#endif
