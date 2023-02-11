#include "spawn.h"

DWORD GetParentProcess()
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != NULL) CloseHandle(hSnapshot);
    }
    return ppid;
}

bool CreatePipes(HANDLE& hInputPipeRead, HANDLE& hInputPipeWrite, HANDLE& hOutputPipeRead, HANDLE& hOutputPipeWrite)
{
    // Create the in/out pipes:
    SECURITY_ATTRIBUTES sec;
    memset(&sec, 0, sizeof(SECURITY_ATTRIBUTES));
    sec.bInheritHandle = 1;
    sec.lpSecurityDescriptor = NULL;
    return (CreatePipe(&hInputPipeRead, &hInputPipeWrite, &sec, BUFFER_SIZE_PIPE) &&
        CreatePipe(&hOutputPipeRead, &hOutputPipeWrite, &sec, BUFFER_SIZE_PIPE) == TRUE);
}

void InitConsole(HANDLE& hOldStdIn, HANDLE& hOldStdOut, HANDLE& hOldStdErr)
{
    hOldStdIn = GetStdHandle(STD_INPUT_HANDLE);
    hOldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    hOldStdErr = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE hStdout = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hStdin = CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
    SetStdHandle(STD_ERROR_HANDLE, hStdout);
    SetStdHandle(STD_INPUT_HANDLE, hStdin);
}

void RestoreStdHandles(HANDLE hOldStdIn, HANDLE hOldStdOut, HANDLE hOldStdErr)
{
    SetStdHandle(STD_OUTPUT_HANDLE, hOldStdOut);
    SetStdHandle(STD_ERROR_HANDLE, hOldStdErr);
    SetStdHandle(STD_INPUT_HANDLE, hOldStdIn);
}

bool EnableVirtualTerminalSequenceProcessing()
{
    bool bRes = false;
    DWORD dwOutConsoleMode = 0;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(hStdOut, &dwOutConsoleMode))
    {
        dwOutConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        bRes = SetConsoleMode(hStdOut, dwOutConsoleMode);
    }
    return bRes;
}

HRESULT CreatePseudoConsoleWithPipes(HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols, OUT HPCON* phPseudoConsole)
{
    HRESULT hRes = E_FAIL;
    if (EnableVirtualTerminalSequenceProcessing())
    {
        COORD consoleCoord = { 0 };
        consoleCoord.X = (short)uiCols;
        consoleCoord.Y = (short)uiRows;
        hRes = CreatePseudoConsole(consoleCoord, hConPtyInputPipeRead, hConPtyOutputPipeWrite, 0, phPseudoConsole);
    }
    return hRes;
}

HRESULT ConfigureProcessThread(HPCON* phPseudoConsole, DWORD_PTR pAttributes, OUT STARTUPINFOEX* pStartupInfo)
{
    HRESULT hRes = E_FAIL;
    SIZE_T pSize = NULL;
    BOOL bSuccess = InitializeProcThreadAttributeList(NULL, 1, 0, &pSize);
    if (pSize != NULL)
    {
        pStartupInfo->StartupInfo.cb = sizeof(STARTUPINFOEX);
        pStartupInfo->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(),
            0,
            pSize
        );
        if (InitializeProcThreadAttributeList(pStartupInfo->lpAttributeList, 1, 0, &pSize) == TRUE)
        {
            if (UpdateProcThreadAttribute(pStartupInfo->lpAttributeList, 0, pAttributes, phPseudoConsole, sizeof(DWORD), NULL, NULL) == TRUE)
            {
                hRes = S_OK;
            }
            else
            {
                cerr << "Could not set pseudoconsole thread attribute. " << GetLastError() << endl;
            }
        }
        else
        {
            cerr << _T("Could not set up attribute list. ") << GetLastError() << endl;
        }
    }
    
    return hRes;
}

HRESULT RunProcess(STARTUPINFOEX& startupInfo, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo)
{
    HRESULT hRes = E_FAIL;
    SECURITY_ATTRIBUTES processSec = { 0 };
    int iSecurityAttributeSize = sizeof(processSec);
    processSec.nLength = iSecurityAttributeSize;
    SECURITY_ATTRIBUTES secAttributes = { 0 };
    secAttributes.nLength = iSecurityAttributeSize;
    if (CreateProcess(NULL, csCommandLine.GetBuffer(), &processSec, &secAttributes, false,
        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&startupInfo, pProcessInfo))
        hRes = S_OK;
    else
        cerr << _T("Could not create process. ") <<  GetLastError() << endl;
    return hRes;
}

HRESULT CreateChildProcessWithPseudoConsole(HPCON* phPseudoConsole, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo)
{
    STARTUPINFOEX startupInfo;
    HRESULT hRes = ConfigureProcessThread(phPseudoConsole, (DWORD_PTR)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, &startupInfo);
    if (SUCCEEDED(hRes))
    {
        hRes = RunProcess(startupInfo, csCommandLine, pProcessInfo);
    }
    return hRes;
}

DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams)
{
    ReadPipeWriteSocketThreadParams* pThreadParams = (ReadPipeWriteSocketThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hPipe;
    SOCKET hSock = pThreadParams->hSock;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bReadSuccess = false;
    DWORD dwBytesSent = 0;
    DWORD dwBytesRead = 0;
    char pBytesToWrite[BUFFER_SIZE_SOCKET];
    do
    {        
        memset(pBytesToWrite, 0, BUFFER_SIZE_SOCKET);
        bReadSuccess = ReadFile(hPipe, pBytesToWrite, BUFFER_SIZE_SOCKET, &dwBytesRead, NULL);
        if (bReadSuccess)
        {
            if(bOverlapped)
                dwBytesSent = send(hSock, pBytesToWrite, (int)dwBytesRead, 0);
            else 
            {
                do
                {
                    dwBytesSent = send(hSock, pBytesToWrite, (int)dwBytesRead, 0);
                } while (WSAGetLastError() == WSAEWOULDBLOCK);
            }
        }
    } while (dwBytesSent > 0 && bReadSuccess);
    return 0;
}

HANDLE StartThreadReadPipeWriteSocket(HANDLE hPipe, SOCKET hSock, bool overlappedSocket)
{
    ReadPipeWriteSocketThreadParams params;
    memset(&params, 0, sizeof(ReadPipeWriteSocketThreadParams));
    params.hPipe = hPipe;
    params.hSock = hSock;
    HANDLE hThread = CreateThread(0, 0, ThreadReadPipeWriteSocket, &params, 0, 0);
    return hThread;
}


DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams)
{
    ReadSocketWritePipeThreadParams* pThreadParams = (ReadSocketWritePipeThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hPipe;
    SOCKET hSock = pThreadParams->hSock;
    HANDLE hChildProcess = pThreadParams->hChildProcess;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bWriteSuccess = false;
    DWORD dwBytesReceived = 0;
    DWORD dwBytesWritten = 0;;
    bool bSocketBlockingOperation = false;
    char pBytesReceived[BUFFER_SIZE_SOCKET];
    if (bOverlapped)
    {
        do
        {
            memset(pBytesReceived, 0, BUFFER_SIZE_SOCKET);
            dwBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
            if(dwBytesReceived > 0)
                bWriteSuccess = WriteFile(hPipe, pBytesReceived, dwBytesReceived, &dwBytesWritten, NULL);
        } while (dwBytesReceived > 0 && bWriteSuccess);
    }
    else
    {
        HANDLE hReadEvent = WSACreateEvent();
        if (hReadEvent != NULL && hReadEvent != INVALID_HANDLE_VALUE)
        {
            // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
            if (WSAEventSelect(hSock, hReadEvent, FD_READ) == 0)
            {
                do
                {
                    memset(pBytesReceived, 0, BUFFER_SIZE_SOCKET);
                    WSAWaitForMultipleEvents(1, &hReadEvent, true, 500, false);
                    dwBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
                    // we still check WSAEWOULDBLOCK for a more robust implementation
                    if (WSAGetLastError() != WSAEWOULDBLOCK)
                    {
                        WSAResetEvent(hReadEvent);
                        bSocketBlockingOperation = false;
                        bWriteSuccess = WriteFile(hPipe, pBytesReceived, dwBytesReceived, &dwBytesWritten, NULL);
                    }
                    else
                    {
                        bSocketBlockingOperation = true;
                    }
                } while (bSocketBlockingOperation || (dwBytesReceived > 0 && bWriteSuccess));
            }
            WSACloseEvent(hReadEvent);
        }
    }
    TerminateProcess(hChildProcess, 0);
}

HANDLE StartThreadReadSocketWritePipe(HANDLE hPipe, SOCKET hSock, HANDLE hChildProcess, bool bOverlappedSocket)
{
    ReadSocketWritePipeThreadParams params;
    memset(&params, 0, sizeof(ReadSocketWritePipeThreadParams));
    params.hPipe = hPipe;
    params.hSock = hSock;
    params.hChildProcess = hChildProcess;
    params.bOverlapped = bOverlappedSocket;
    HANDLE hThread = CreateThread(0, 0, ThreadReadSocketWritePipe, &params, 0, 0);
    return hThread;
}