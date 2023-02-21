#ifndef _SPAWN_H_
#define _SPAWN_H_

#include "stdafx.h"
#include "wininternal.h"
#include "hijacking.h"


#define BUFFER_SIZE_PIPE 1048576

#define BUFFER_SIZE_SOCKET 8192

DWORD  GetParentProcessId(DWORD dwProcessId = 0);

HANDLE GetProcessHandle(DWORD dwProcessId);

bool GetProcessCwd(DWORD dwProcessId, CString& csCurrentWorkingDirectory);

bool CreatePipes(HANDLE& hInputPipeRead, HANDLE& hInputPipeWrite, HANDLE& hOutputPipeRead, HANDLE& hOutputPipeWrite);

void InitConsole(HANDLE& hOldStdIn, HANDLE& hOldStdOut, HANDLE& hOldStdErr);

void RestoreStdHandles(HANDLE hOldStdIn, HANDLE hOldStdOut, HANDLE hOldStdErr);

bool EnableVirtualTerminalSequenceProcessing();

HRESULT CreatePseudoConsoleWithPipes(HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols, OUT HPCON* phPseudoConsole);

HRESULT ConfigureProcessThread(HPCON hPseudoConsole, DWORD_PTR pAttributes, OUT STARTUPINFOEX* pStartupInfo);

HRESULT RunProcess(STARTUPINFOEX& startupInfo, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo);

HRESULT CreateChildProcessWithPseudoConsole(HPCON hPseudoConsole, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo);


typedef struct _CommunicationThreadParams
{
	char* pPopenControlCode;
	char* pPtyControlCode;
	HANDLE hInPipe;
	HANDLE hOutPipe;
	SOCKET hSock;
	PROCESS_INFORMATION piInfo;
	HANDLE hBlockWriteSockThread;
	bool bOverlapped;
} CommunicationThreadParams; 

DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams);

HANDLE StartThreadReadPipeWriteSocket(CommunicationThreadParams* pParams);

int CheckBufferMatch(char* pBuf, int iBufSize, char* pNewData, int iNewDataSize, char* pControlBuf, int iControlBufSize, char* pRemainBuf, int* pRemainSize);

bool ReadSockWritePipe(SOCKET hSock, HANDLE hPipe, bool bOverlapped);

DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams);

HANDLE StartThreadReadSocketWritePipe(CommunicationThreadParams* pParams);

typedef NTSTATUS(NTAPI* NtSuspendProcessPtr)(
	HANDLE	ProcessHandle
);

typedef NTSTATUS(NTAPI* NtResumeProcessPtr)(
	HANDLE	ProcessHandle
);

HRESULT SpawnPty(CString csCommandLine, DWORD dwRows, DWORD dwCols, char* pPopenControlString, char* pPtyControlString);

#endif
